package nz.ac.aut.hss.card.client;

import javacard.framework.UserException;
import javacard.security.AESKey;
import javacard.security.PublicKey;

import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */
public class RemoteObjectImpl implements RemoteObject {
	private final Security security;
	private final PublicKey publicKey;

	public RemoteObjectImpl(final Security security, final PublicKey publicKey) {
		this.security = security;
		this.publicKey = publicKey;
	}

	public PublicKey getPublicKey() throws RemoteException, UserException {
		return publicKey;
	}

	public void setSecretKey(final AESKey key) throws RemoteException, UserException {
		security.setKey(key);
	}
}
