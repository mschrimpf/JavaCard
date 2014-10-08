package nz.ac.aut.hss.card.client;

import javacard.framework.UserException;
import javacard.security.AESKey;
import javacard.security.PublicKey;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */
public interface RemoteObject extends Remote {
	public void enterPIN(byte[] pinBytes) throws RemoteException, UserException;

	public PublicKey getPublicKey() throws RemoteException, UserException;

	public void setSecretKey(AESKey key) throws RemoteException, UserException;
}
