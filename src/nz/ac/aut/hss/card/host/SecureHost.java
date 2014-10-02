package nz.ac.aut.hss.card.host;

import com.sun.javacard.clientlib.ApduIOCardAccessor;
import com.sun.javacard.clientlib.CardAccessor;
import com.sun.javacard.rmiclientlib.JCRMIConnect;
import nz.ac.aut.hss.card.client.SecureRMIGreeting;

import java.rmi.RemoteException;

/**
 * A simple Java Card host application that demonstrates a JCRMI host
 * which uses a card accessor to handle encryption of the APDU
 * Note: Requires Java Card Development Kit and Ant to be installed.
 * Use the following command line statements from the directory that
 * contains the file build.xml and the config file jcclient.properties
 * Build (compile) this host application using:
 * ant build-host
 * To run first SecureRMIDemoApplet applet should be built, deployed,
 * installed, and the Java Card Development Kit simulator started via:
 * ant start-cad (or start in separate command window)
 * Then this host application can be run via:
 * ant run-host
 */
public class SecureHost {
	public static void main(String[] args) {
		CardAccessor ca = null;
		try {  // connect to the CAD specified in file jcclient.properties
			// using a secure card accessor
			ca = new SecureAccessor(new ApduIOCardAccessor());
			JCRMIConnect jcRMI = new JCRMIConnect(ca);
			// select the RMIDemoApplet
			System.out.println("Selecting secure applet");
			byte[] appletAID = {0x10, 0x20, 0x30, 0x40, 0x50, 0x03};
			jcRMI.selectApplet(appletAID,
					JCRMIConnect.REF_WITH_INTERFACE_NAMES);
			// obtain a proxy stub
			System.out.println("Getting proxy for remote object");
			SecureRMIGreeting remoteProxy = (SecureRMIGreeting) jcRMI.getInitialReference();
			System.out.println("Securely calling a remote method");
			System.out.println("Greeting is "
					+ new String(remoteProxy.getGreeting()));
			remoteProxy.setGreeting("Ssshhhhhh!".getBytes());
			System.out.println("Greeting is "
					+ new String(remoteProxy.getGreeting()));

//			System.out.println("Getting public key");
//			RemoteObject remoteProxy = (RemoteObject) jcRMI.getInitialReference();
//			PublicKey cardPublicKey = remoteProxy.getPublicKey();
//			AESKey secretKey = generateSecretKey();
//			remoteProxy.setSecretKey(secretKey);
		} catch (RemoteException e) {
			System.err.println("Remote Exception: " + e);
		} catch (Exception e) {
			System.err.println("Exception from applet: " + e);
		} finally {
			try {
				if (ca != null) ca.closeCard();
			} catch (Exception e) {
				System.err.println("Unable to close card");
			}
		}
	}
}
