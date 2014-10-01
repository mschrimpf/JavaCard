package nz.ac.aut.hss.card.host;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */

import com.sun.javacard.clientlib.ApduIOCardAccessor;
import com.sun.javacard.clientlib.CardAccessor;
import com.sun.javacard.rmiclientlib.JCRMIConnect;
import nz.ac.aut.hss.card.client.SecureRMIGreeting;

import java.rmi.RemoteException;

public class SecureAppletHost {
	public static void main(String[] args) {
		CardAccessor ca = null;
		try {  // connect to the CAD specified in file jcclient.properties
			ca = new ApduIOCardAccessor();
			JCRMIConnect jcRMI = new JCRMIConnect(ca);
			// select the RMIDemoApplet
			System.out.println("Selecting applet");
			byte[] appletAID = {0x10, 0x20, 0x30, 0x40, 0x50, 0x03};
			jcRMI.selectApplet(appletAID, JCRMIConnect.REF_WITH_INTERFACE_NAMES);
			// obtain a proxy stub
			System.out.println("Getting proxy for remote object");
			SecureRMIGreeting remoteProxy = (SecureRMIGreeting) jcRMI.getInitialReference();
			System.out.println("Calling a remote method");
			System.out.println("Greeting is " + new String(remoteProxy.getGreeting()));
			remoteProxy.setGreeting("Hi there".getBytes());
			System.out.println("Changed greeting is " + new String(remoteProxy.getGreeting()));

//			System.out.println("Getting public key");
//			RemoteObject remoteProxy = (RemoteObject) jcRMI.getInitialReference();
//			PublicKey cardPublicKey = remoteProxy.getPublicKey();
//			AESKey secretKey = generateSecretKey();
//			remoteProxy.setSecretKey(secretKey);
		} catch (RemoteException e) {
			System.err.println("Remote Exception: " + e);
		} catch (Exception e) {
			System.err.println("Unable to select applet: " + e);
		} finally {
			try {
				if (ca != null) ca.closeCard();
			} catch (Exception e) {
				System.err.println("Unable to close card");
			}
		}
	}
}
