package nz.ac.aut.hss.card.client;

import javacard.framework.ISOException;
import javacard.framework.UserException;
import javacard.framework.service.CardRemoteObject;
import javacard.security.AESKey;
import javacard.security.PublicKey;

import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */
public class RemoteObjectImpl implements RemoteObject {
	/** signal that PIN verification failed */
	public final static short SW_VERIFICATION_FAILED = 0x6300;

	private final Security security;
	private final PublicKey publicKey;
	private final SecureApplet applet;

	public RemoteObjectImpl(final Security security, final PublicKey publicKey, final SecureApplet applet) {
		this.security = security;
		this.publicKey = publicKey;
		this.applet = applet;
		CardRemoteObject.export(this); // export this remote object
	}

	public void enterPIN(byte[] pinBytes) throws RemoteException, UserException {
		short offset = 0;
		byte length = (byte) pinBytes.length;
		if (applet.checkPIN(pinBytes, offset, length)) {
			return; // works
		}
		if (applet.getPINTriesRemaining() < 1) {
			// delete data
			publicKey.clearKey();
			security.clearKey();
		}
		ISOException.throwIt(SW_VERIFICATION_FAILED);
	}

	public PublicKey getPublicKey() throws RemoteException, UserException {
		assurePINSet();
		return publicKey;
	}

	public void setSecretKey(final AESKey key) throws RemoteException, UserException {
		assurePINSet();
		security.setKey(key);
	}

	private void assurePINSet() {
//		if (!applet.isPINValidated())
//			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}
}
