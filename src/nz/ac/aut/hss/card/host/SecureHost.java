package nz.ac.aut.hss.card.host;

import com.sun.javacard.clientlib.ApduIOCardAccessor;
import com.sun.javacard.rmiclientlib.JCRMIConnect;
import javacard.framework.UserException;
import nz.ac.aut.hss.card.client.KeySpec;
import nz.ac.aut.hss.card.client.RemoteObject;

import javax.crypto.SecretKey;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.util.Scanner;

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
			// System.out.println(publicKey);
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

            System.out.println("Welcome, Please enter your pin: ");
            Scanner input = new Scanner(System.in);
            byte[] values;
            String s = input.nextLine();
            String[] str = s.split(" ");
            values = new byte[str.length];
            int x = 0;
            for(String i : str){
                values[x] = (byte) (Integer.parseInt(i));
                x++;
            }
            
            boolean correct = enterPin(remote, values, "");
            while(!correct){
                System.out.println("Please try again, enter your pin: ");
                s = input.nextLine();
                str = s.split(" ");
                values = new byte[str.length];
                x = 0;
                for(String i : str){
                    values[x] = (byte) (Integer.parseInt(i));
                    x++;
                }
                correct = enterPin(remote, values, "");
            }
            System.out.println();
            System.out.println("Thank you");
            System.out.println();
            int[] options = {1, 2, 3, 4, 5};
            System.out.println("Access Granted");
                    System.out.println("MENU");
                    System.out.println("1: \t Get Cardholder Name");
                    System.out.println("2: \t Get Account Number");
                    System.out.println("3: \t Get Expiry Date");
                    System.out.println("4: \t Get Security Code");
                    System.out.println("5: \t Quit");
            
            s = input.nextLine();
            int choice = Integer.parseInt(s);
            while(choice!=5){
                while(choice!=1 && choice!=2 && choice!=3 && choice!=4 && choice!=5){
                    System.out.println("Sorry that was not an option");
                    System.out.println("MENU");
                    System.out.println("1: \t Get Cardholder Name");
                    System.out.println("2: \t Get Account Number");
                    System.out.println("3: \t Get Expiry Date");
                    System.out.println("4: \t Get Security Code");
                    System.out.println("5: \t Quit");
                    s = input.nextLine();
                    choice = Integer.parseInt(s);
                    System.out.println();
                }
                while(choice==1){
                    byte[] name = remote.getName();
                    System.out.printf("%20s: %10s\n", "Cardholder: ", new String(name));
                    System.out.println("MENU");
                    System.out.println("1: \t Get Cardholder Name");
                    System.out.println("2: \t Get Account Number");
                    System.out.println("3: \t Get Expiry Date");
                    System.out.println("4: \t Get Security Code");
                    System.out.println("5: \t Quit");
                    s = input.nextLine();
                    choice = Integer.parseInt(s);
                    System.out.println();
                }
                while(choice==2){		
                    byte[] accountNumber = remote.getAccountNumber();
                    System.out.printf("%20s: %10s\n", "Account number: ", new String(accountNumber));
                    System.out.println("MENU");
                    System.out.println("1: \t Get Cardholder Name");
                    System.out.println("2: \t Get Account Number");
                    System.out.println("3: \t Get Expiry Date");
                    System.out.println("4: \t Get Security Code");
                    System.out.println("5: \t Quit");
                    s = input.nextLine();
                    choice = Integer.parseInt(s);
                    System.out.println();
                }
                while(choice==3){
                    byte[] expiryDate = remote.getExpiryDate();
                    System.out.printf("%20s: %10s\n", "Expiry date: ", new String(expiryDate));
                    System.out.println("MENU");
                    System.out.println("1: \t Get Cardholder Name");
                    System.out.println("2: \t Get Account Number");
                    System.out.println("3: \t Get Expiry Date");
                    System.out.println("4: \t Get Security Code");
                    System.out.println("5: \t Quit");
                    s = input.nextLine();
                    choice = Integer.parseInt(s);
                    System.out.println();
                }
                while(choice==4){
                    byte[] securityCode = remote.getSecurityCode();
                    System.out.printf("%20s: %10s\n", "Security code", new String(securityCode));
                    System.out.println("MENU");
                    System.out.println("1: \t Get Cardholder Name");
                    System.out.println("2: \t Get Account Number");
                    System.out.println("3: \t Get Expiry Date");
                    System.out.println("4: \t Get Security Code");
                    System.out.println("5: \t Quit");
                    s = input.nextLine();
                    choice = Integer.parseInt(s);
                    System.out.println();
                }
           }
           System.out.println("Quitting");
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

	private static boolean enterPin(final RemoteObject remoteProxy, final byte[] pinBytes, String label)
			throws RemoteException, UserException {
		final short pinTriesRemaining;
		printPin(label, pinBytes);
		pinTriesRemaining = remoteProxy.checkPIN(pinBytes);
		System.out.println("PIN is " +
				(pinTriesRemaining == -1 ? "correct" : "incorrect - " + pinTriesRemaining + " attempts remaining"));
        if(pinTriesRemaining == -1){
            return true;
        }else{
            return false;
        }
	}

	private static void printPin(final String pinDescription, final byte[] pinBytes) {
		System.out.print("Entering " + pinDescription + " PIN:");
		for (byte pinByte : pinBytes) {
			System.out.print(" " + pinByte);
		}
		System.out.println();
	}
}
