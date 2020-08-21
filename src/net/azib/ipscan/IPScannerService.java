package net.azib.ipscan;

import net.azib.ipscan.config.CommentsConfig;
import net.azib.ipscan.config.Platform;
import net.azib.ipscan.config.ScannerConfig;
import net.azib.ipscan.core.*;
import net.azib.ipscan.core.net.PingerRegistry;
import net.azib.ipscan.core.state.ScanningState;
import net.azib.ipscan.core.state.StateMachine;
import net.azib.ipscan.core.state.StateTransitionListener;
import net.azib.ipscan.feeders.Feeder;
import net.azib.ipscan.feeders.RangeFeeder;
import net.azib.ipscan.fetchers.*;

import java.net.InetAddress;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static java.util.Arrays.asList;
import static net.azib.ipscan.core.state.ScanningState.IDLE;

public class IPScannerService implements ScanningProgressCallback, ScanningResultCallback, StateTransitionListener {

	static {
		Security.setProperty("networkaddress.cache.ttl", "0");
		Security.setProperty("networkaddress.cache.negative.ttl", "0");
	}

	private final PingerRegistry pingerRegistry;
	private final Scanner scanner;
	private final StateMachine stateMachine;
	private final ScannerConfig scannerConfig;
	private final IPScannerContext ipScannerContext;
	private final FetcherRegistry fetcherRegistry;

	private ScannerDispatcherThread scannerThread;
	private Feeder feeder;

	public IPScannerService(Fetcher... fetchers) {
		Preferences preferences = Preferences.userRoot().node("ipscan");
		this.scannerConfig = new ScannerConfig(preferences);
		this.pingerRegistry = new PingerRegistry(scannerConfig);

		this.stateMachine = new StateMachine() {
		};
		this.stateMachine.addTransitionListener(this);

		MACFetcher macFetcher = Platform.WINDOWS ? new WinMACFetcher() : new UnixMACFetcher();
		this.fetcherRegistry = new FetcherRegistry(asList(
				new IPFetcher(),
				new PingFetcher(pingerRegistry, scannerConfig),
				new PingTTLFetcher(pingerRegistry, scannerConfig),
				new HostnameFetcher(),
				new WebDetectFetcher(scannerConfig),
				new HTTPSenderFetcher(scannerConfig),
				new PacketLossFetcher(pingerRegistry, scannerConfig),
				new NetBIOSInfoFetcher(),
				new CommentFetcher(new CommentsConfig(preferences)),
				new PortsFetcher(scannerConfig),
				new MACVendorFetcher(macFetcher),
				macFetcher), preferences, null);
		String[] initialFetchers = Stream.of(fetchers).map(f -> f.id).toArray(String[]::new);
		fetcherRegistry.updateSelectedFetchers(initialFetchers);
		this.scanner = new Scanner(fetcherRegistry);
		this.ipScannerContext = new IPScannerContext(fetcherRegistry, stateMachine);
		this.stateMachine.init();
	}

	@Override
	public void updateProgress(InetAddress currentAddress, int runningThreads, int percentageComplete) {
		this.ipScannerContext.currentAddress = currentAddress;
		this.ipScannerContext.runningThreads = runningThreads;
		this.ipScannerContext.percentageComplete = percentageComplete;
	}

	@Override
	public void prepareForResults(ScanningResult result) {
		if (this.ipScannerContext.scanningResults.isRegistered(result)) {
			// just redraw the item
			this.ipScannerContext.scanningResults.update(result);
		}
		else {
			this.ipScannerContext.scanningResults.registerAtIndex(0, result);
		}
	}

	@Override
	public void consumeResults(ScanningResult result) {
		this.prepareForResults(result);
	}

	private ScannerDispatcherThread createScannerThread(Feeder feeder, ScanningProgressCallback progressCallback, ScanningResultCallback resultsCallback) {
		return new ScannerDispatcherThread(feeder, scanner, stateMachine, progressCallback, this.ipScannerContext.scanningResults, scannerConfig, resultsCallback);
	}

	public void updateFetchers(List<Fetcher> fetchers) {
		this.fetcherRegistry.updateSelectedFetchers(fetchers.stream().map(f -> f.id).toArray(String[]::new));
	}

	public void startScan(String startIP, String endIP) {
		this.feeder = new RangeFeeder(startIP, endIP);
		if (stateMachine.inState(IDLE)) {
			if (!this.pingerRegistry.checkSelectedPinger())
				throw new IllegalStateException("Unable to start ip scanner");
		}
		stateMachine.transitionToNext();
	}

	@Override
	public void transitionTo(ScanningState state, StateMachine.Transition transition) {
		this.ipScannerContext.state = transition;
		switch (state) {
			case STARTING:
			case RESTARTING:
				if (transition != StateMachine.Transition.CONTINUE) {
					this.ipScannerContext.clear();
				}
				try {
					scannerThread = createScannerThread(feeder, this, this);
					stateMachine.startScanning();
				}
				catch (RuntimeException e) {
					stateMachine.reset();
					throw e;
				}
				break;
			case SCANNING:
				scannerThread.start();
				break;
		}
	}

	public final class IPScannerContext {
		public int runningThreads;
		public InetAddress currentAddress;
		public int percentageComplete;
		public StateMachine.Transition state;
		public final ScanningResultList scanningResults;

		public IPScannerContext(FetcherRegistry fetcherRegistry, StateMachine stateMachine) {
			this.scanningResults = new ScanningResultList(fetcherRegistry, stateMachine);
		}

		public void clear() {
			scanningResults.clear();
			runningThreads = 0;
			currentAddress = null;
			percentageComplete = 0;
		}

		public List<ResultValue> getScanningResults() {
			if (scanningResults.getFetchers() != null) {
				List<Integer> indexes = new ArrayList<>(Fetcher.values().length);
				for (Fetcher fetcher : Fetcher.values()) {
					indexes.add(scanningResults.getFetcherIndex(fetcher.id));
				}

				return StreamSupport.stream(scanningResults.spliterator(), false)
						.map(sr -> new ResultValue(sr, indexes)).collect(Collectors.toList());
			}
			return Collections.emptyList();
		}
	}

	public ScannerConfig getScannerConfig() {
		return scannerConfig;
	}

	public IPScannerContext getIpScannerContext() {
		return ipScannerContext;
	}

	public static class ResultValue {
		public final String hostname;
		public final String address;
		public final String ping;
		public final String pingTTL;
		public final String webDetectValue;
		public final String httpSenderValue;
		public final String packetLoss;
		public final String netBIOSInfo;
		public final String comment;
		public final String ports;
		public final String macVendorValue;
		public final String ipFetcherValue;
		public final String macFetcherValue;
		public final ScanningResult.ResultType type;

		public ResultValue(ScanningResult scanningResult, List<Integer> indexes) {
			this.address = scanningResult.getAddress().toString();
			this.type = scanningResult.getType();
			this.ipFetcherValue = nullSafeValue(scanningResult, indexes.get(0));
			this.ping = nullSafeValue(scanningResult, indexes.get(1));
			this.pingTTL = nullSafeValue(scanningResult, indexes.get(2));
			this.hostname = nullSafeValue(scanningResult, indexes.get(3));
			this.webDetectValue = nullSafeValue(scanningResult, indexes.get(4));
			this.httpSenderValue = nullSafeValue(scanningResult, indexes.get(5));
			this.packetLoss = nullSafeValue(scanningResult, indexes.get(6));
			this.netBIOSInfo = nullSafeValue(scanningResult, indexes.get(7));
			this.comment = nullSafeValue(scanningResult, indexes.get(8));
			this.ports = nullSafeValue(scanningResult, indexes.get(9));
			this.macVendorValue = nullSafeValue(scanningResult, indexes.get(10));
			this.macFetcherValue = nullSafeValue(scanningResult, indexes.get(11));
		}

		private String nullSafeValue(ScanningResult scanningResult, int index) {
			Object ret = scanningResult.getValues().get(index);
			return ret == null ? null : ret.toString();
		}
	}

	public enum Fetcher {
		IPFetcher(net.azib.ipscan.fetchers.IPFetcher.ID),
		PingFetcher(net.azib.ipscan.fetchers.PingFetcher.ID),
		PingTTLFetcher(net.azib.ipscan.fetchers.PingTTLFetcher.ID),
		HostnameFetcher(net.azib.ipscan.fetchers.HostnameFetcher.ID),
		WebDetectFetcher("fetcher.webDetect"),
		HTTPSenderFetcher("fetcher.httpSender"),
		PacketLossFetcher(net.azib.ipscan.fetchers.PacketLossFetcher.ID),
		NetBIOSInfoFetcher("fetcher.netbios"),
		CommentFetcher(net.azib.ipscan.fetchers.CommentFetcher.ID),
		PortsFetcher(net.azib.ipscan.fetchers.PortsFetcher.ID),
		MACVendorFetcher(net.azib.ipscan.fetchers.MACVendorFetcher.ID),
		MACFetcher(net.azib.ipscan.fetchers.MACFetcher.ID);

		private final String id;

		Fetcher(String id) {
			this.id = id;
		}
	}
}
