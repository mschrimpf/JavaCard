package nz.ac.aut.hss.card.client;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.UserException;
import javacard.framework.service.CardRemoteObject;
import javacard.framework.service.*;
import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */
public class RemoteObjectImpl implements RemoteObject {
	/** signal that PIN verification failed */
	public final static short SW_VERIFICATION_FAILED = 0x6300;
	private static final short REQUEST_DENIED = (short) 0x6003;

	private final byte[] name, accNum, securityCode, expiryDate;

	private final Security security;
	private final byte[] publicKeyBytes;
	private final SecureApplet applet;

	public RemoteObjectImpl(final Security security, final byte[] publicKeyBytes, final SecureApplet applet) {
		// references
		if (security == null)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		this.security = security;
		if (publicKeyBytes == null)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		this.publicKeyBytes = publicKeyBytes;
		if (applet == null)
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		this.applet = applet;

		// account details
		// put a NAME in a transient array
		name = new byte[3];
		name[0] = 0x5A;
		name[1] = 0x6F;
		name[2] = 0x65;

		// put an ACCOUNT NUMBER in a transient array
		accNum = new byte[6];
		accNum[0] = 0x39;
		accNum[1] = 0x38;
		accNum[2] = 0x37;
		accNum[3] = 0x36;
		accNum[4] = 0x35;
		accNum[5] = 0x34;

		// put an EXPIRYDATE in a transient array
		expiryDate = new byte[4];
		expiryDate[0] = 0x30;
		expiryDate[1] = 0x37;
		expiryDate[2] = 0X31;
		expiryDate[3] = 0x35;

		// put a SECURITY CODE in a transient array
		securityCode = new byte[3];
		securityCode[0] = 0x37;
		securityCode[1] = 0x37;
		securityCode[2] = 0x37;

		// export
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
		clearArray(name);
		clearArray(accNum);
		clearArray(expiryDate);
		clearArray(securityCode);
	}

	public byte[] getPublicKeyBytes() throws RemoteException, UserException {
		return publicKeyBytes;
	}

	public void useAsymmetricEncryption() throws RemoteException, UserException {
		security.usePrivateKey();
	}

	public void setSecretKey(final byte[] keyBytes) throws RemoteException, UserException {
		assurePIN();
		security.setSessionKey(keyBytes);
	}

	public void useSymmetricEncryption() throws RemoteException, UserException {
		assurePIN();
		security.useSymmetric();
	}

	private void clearArray(byte[] array) {
		for (short i = 0; i < array.length; i++) {
			array[i] = 0;
		}
	}

	// details

	public byte[] getName() throws RemoteException, UserException {
		assurePINAndConfidentiality();
		return name;
	}

	public byte[] getAccountNumber() throws RemoteException, UserException {
		assurePINAndConfidentiality();
		return accNum;
	}

	public byte[] getExpiryDate() throws RemoteException, UserException {
		assurePINAndConfidentiality();
		return expiryDate;
	}

	public byte[] getSecurityCode() throws RemoteException, UserException {
		assurePINAndConfidentiality();
		return securityCode;
	}

	// security

	private void assurePINAndConfidentiality() throws UserException {
		assurePIN();
		assureConfidentiality();
	}

	private void assureConfidentiality() throws UserException {
//		if (!security.isCommandSecure
//				(SecurityService.PROPERTY_OUTPUT_CONFIDENTIALITY))
//			UserException.throwIt(REQUEST_DENIED);
		if(! security.isAuthenticated(SecurityService.PRINCIPAL_CARDHOLDER))
			UserException.throwIt(SW_VERIFICATION_FAILED);
	}

	private void assurePIN() {
		if (!applet.isPINValidated())
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
	}
}
