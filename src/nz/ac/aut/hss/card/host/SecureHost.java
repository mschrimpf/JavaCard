package nz.ac.aut.hss.card.host;

import com.sun.javacard.clientlib.ApduIOCardAccessor;
import com.sun.javacard.rmiclientlib.JCRMIConnect;
import javacard.framework.UserException;
import nz.ac.aut.hss.card.client.KeySpec;
import nz.ac.aut.hss.card.client.RemoteObject;

import javax.crypto.SecretKey;
import java.rmi.RemoteException;
import java.security.PublicKey;

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
		SecureAccessor accessor = null;
		try {
			// connect to the CAD specified in file jcclient.properties
			// using a secure card accessor
			accessor = new SecureAccessor(new ApduIOCardAccessor());
			JCRMIConnect jcRMI = new JCRMIConnect(accessor);
			// select the RMIDemoApplet
			System.out.println("Selecting secure applet");
			byte[] appletAID = {0x10, 0x20, 0x30, 0x40, 0x50, 0x05};
			jcRMI.selectApplet(appletAID, JCRMIConnect.REF_WITH_INTERFACE_NAMES);
			// obtain a proxy stub
			System.out.println("Getting proxy for remote object");
			RemoteObject remote = (RemoteObject) jcRMI.getInitialReference();
			System.out.println("Got remote object");

			// public key
			System.out.println("Retrieving public key");
			byte[] publicKeyBytes = remote.getPublicKeyBytes();
			final PublicKey publicKey = KeyUtil.toKey(publicKeyBytes);
			System.out.println(publicKey);
//			System.out.println("Using asymmetric encryption");
//			remote.useAsymmetricEncryption();
//			accessor.setPublicKey(publicKey);
//			System.out.println("OK");

			// session key
			System.out.println("Generating session key");
			SecretKey secretKey = KeyUtil.generateAESKey(KeySpec.SESSION_KEY_LENGTH_BITS);
			System.out.println("Setting session key on remote");
			remote.setSecretKey(secretKey.getEncoded());
			System.out.println("Using symmetric encryption");
			remote.useSymmetricEncryption();
			accessor.setSessionKey(secretKey);
			System.out.println("OK");

			System.out.println();

			// PIN
			final byte[] incorrectPinBytes = {0x01, 0x02, 0x03, 0x04};
			enterPin(remote, incorrectPinBytes, "incorrect");

			final byte[] pinBytes = {0x04, 0x03, 0x02, 0x01};
			enterPin(remote, pinBytes, "correct");

			System.out.println();

			// get details
			System.out.println("Retrieving details");
			byte[] name = remote.getName();
			System.out.printf("%20s: %10s\n", "Account name", new String(name));
			byte[] accountNumber = remote.getAccountNumber();
			System.out.printf("%20s: %10s\n", "Account number", new String(accountNumber));
			byte[] expiryDate = remote.getExpiryDate();
			System.out.printf("%20s: %10s\n", "Expiry date", new String(expiryDate));
			byte[] securityCode = remote.getSecurityCode();
			System.out.printf("%20s: %10s\n", "Security code", new String(securityCode));
		} catch (RemoteException e) {
			System.err.println("Remote Exception: " + e);
			e.printStackTrace();
		} catch (Exception e) {
			System.err.println("Exception from applet: " + e);
			e.printStackTrace();
		} finally {
			try {
				if (accessor != null) accessor.closeCard();
			} catch (Exception e) {
				System.err.println("Unable to close card");
			}
		}
	}

	private static void print(final String description, final byte[] bytes) {
		System.out.print(description + ":");
		for (int i = 0; i < bytes.length; i++) {
			System.out.printf(" [%d] 0x%02X", i, bytes[i]);
		}
		System.out.println();
	}

	private static void enterPin(final RemoteObject remoteProxy, final byte[] pinBytes, String label)
			throws RemoteException, UserException {
		final short pinTriesRemaining;
		printPin(label, pinBytes);
		pinTriesRemaining = remoteProxy.checkPIN(pinBytes);
		System.out.println("PIN is " +
				(pinTriesRemaining == -1 ? "correct" : "incorrect - " + pinTriesRemaining + " attempts remaining"));
	}

	private static void printPin(final String pinDescription, final byte[] pinBytes) {
		System.out.print("Entering " + pinDescription + " PIN:");
		for (byte pinByte : pinBytes) {
			System.out.print(" " + pinByte);
		}
		System.out.println();
	}
}
