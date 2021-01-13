package net.azib.ipscan.gui.actions;

import net.azib.ipscan.config.LoggerFactory;
import net.azib.ipscan.feeders.FeederException;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.TraverseEvent;
import org.eclipse.swt.events.TraverseListener;
import org.eclipse.swt.widgets.*;

import java.net.*;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Comparator.comparing;
import static net.azib.ipscan.util.InetAddressUtils.getNetworkInterfaces;

/**
 * FeederActions
 * TODO: tests
 *
 * @author Anton Keks
 */
public class FeederActions {
	
	static final Logger LOG = LoggerFactory.getLogger();

	public static class HostnameButton extends SelectionAdapter implements TraverseListener {
		private Text hostnameText;
		private Text ipText;
        private Combo netmaskCombo;

		public HostnameButton(Text hostnameText, Text ipText, Combo netmaskCombo) {
			this.hostnameText = hostnameText;
			this.ipText = ipText;
            this.netmaskCombo = netmaskCombo;
        }
		
		public void widgetSelected(SelectionEvent event) {
			String hostname = hostnameText.getText();
			
			try {				
				if (hostname.equals(InetAddress.getLocalHost().getHostName())) {
					askLocalIPAddress();
				}
				else {
					// resolve remote address
					InetAddress address = InetAddress.getByName(hostname);
					ipText.setText(address.getHostAddress());

					// now update the hostname itself using a reverse lookup
					String realHostname = address.getCanonicalHostName();
					if (!address.getHostAddress().equals(realHostname)) {
						// if a hostname was returned, not the same IP address
						hostnameText.setText(realHostname);
						hostnameText.setSelection(realHostname.length());
					}	
				}
			}
			catch (UnknownHostException e) {
				throw new FeederException("invalidHostname");
			}
		}
		
		public void keyTraversed(TraverseEvent e) {
			if (e.detail == SWT.TRAVERSE_RETURN) {
				widgetSelected(null);
				e.doit = false;
			}
		}
		
		/**
		 * Asks user which local IP address they want to use 
		 */
		private void askLocalIPAddress() {
			try {
				Menu popupMenu = new Menu(Display.getCurrent().getActiveShell(), SWT.POP_UP);
				Listener menuItemListener = event -> {
					MenuItem menuItem = (MenuItem) event.widget;
					String address = (String) menuItem.getData();
					ipText.setText(address.substring(0, address.lastIndexOf('/')));
					netmaskCombo.setText(address.substring(address.lastIndexOf('/')));
					menuItem.getParent().dispose();
				};

				for (NetworkInterface networkInterface : getNetworkInterfaces()) {
					List<InterfaceAddress> addresses = networkInterface.getInterfaceAddresses();
					addresses.sort(comparing(i -> i.getAddress().getAddress().length));
					for (InterfaceAddress ifaddr : addresses) {
						if (ifaddr == null) continue;
                        InetAddress address = ifaddr.getAddress();
                        if (!address.isLoopbackAddress()) {
							MenuItem menuItem = new MenuItem(popupMenu, 0);
							String ip = address.getHostAddress();
							menuItem.setText(networkInterface.getDisplayName() + ": " + ip);
							menuItem.setData(ip + "/" + ifaddr.getNetworkPrefixLength());
							menuItem.addListener(SWT.Selection, menuItemListener);
						}
					}					
				}
				
				if (popupMenu.getItemCount() > 1) {
					popupMenu.setLocation(Display.getCurrent().getCursorLocation());
					popupMenu.setVisible(true);
				}
				else {
					// emulate click on the single menu item
					if (popupMenu.getItemCount() == 1) {
						Event event = new Event();
						event.widget = popupMenu.getItem(0);
						menuItemListener.handleEvent(event);
						popupMenu.dispose();
					}
					// otherwise, unable to retrieve any sane local addresses,
					// leave the field as-is, which probably shows the loopback address already
				}
			}
			catch (SocketException e) {
				LOG.log(Level.FINE, "Cannot enumerate network interfaces", e);
			}
		}
	}

}

