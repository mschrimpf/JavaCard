package nz.ac.aut.hss.card.client;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.UserException;
import javacard.framework.service.CardRemoteObject;
import javacard.framework.service.SecurityService;
import javacard.security.AESKey;

import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */
public class RemoteObjectImpl implements RemoteObject {
	/** signal that PIN verification failed */
	public final static short SW_VERIFICATION_FAILED = 0x6300;
	private static final short REQUEST_DENIED = (short) 0x6003;

	private final Security security;
	private final byte[] publicKeyBytes;
	private final SecureApplet applet;

	public RemoteObjectImpl(final Security security, final byte[] publicKeyBytes, final SecureApplet applet) {
		this.security = security;
		this.publicKeyBytes = publicKeyBytes;
		this.applet = applet;
		CardRemoteObject.export(this); // export this remote object
	}

	public short checkPIN(byte[] pinBytes) throws RemoteException, UserException {
		short offset = 0;
		byte length = (byte) pinBytes.length;
		if (applet.checkPIN(pinBytes, offset, length)) {
			return -1;
		}
		final short triesRemaining = applet.getPINTriesRemaining();
		if (triesRemaining < 1) {
			// delete data if pin entered wrongly too many times
			clearData();
		}
		return triesRemaining;
	}

	private void clearData() {
		clearArray(publicKeyBytes);
		security.clearKey();
	}

	public byte[] getPublicKeyBytes() throws RemoteException, UserException {
		assurePIN();
		return publicKeyBytes;
	}

	public void setSecretKey(final AESKey key) throws RemoteException, UserException {
		assurePINAndConfidentiality();
		security.setKey(key);
	}

	private void assurePINAndConfidentiality() throws UserException {
		assurePIN();
		assureConfidentiality();
	}

	private void assureConfidentiality() throws UserException {
		if (!security.isCommandSecure
				(SecurityService.PROPERTY_OUTPUT_CONFIDENTIALITY))
			UserException.throwIt(REQUEST_DENIED);
	}

	private void assurePIN() {
		if (!applet.isPINValidated())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}

	private void clearArray(byte[] array) {
		for (short i = 0; i < array.length; i++) {
			array[i] = 0;
		}
	}
}
