package nz.ac.aut.hss.card.client;

import javacard.framework.UserException;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 30.09.2014
 */
public interface RemoteObject extends Remote {
	/**
	 * @return -1 if the pin entered is correct, the amount of tries remaining otherwise
	 */
	public short checkPIN(byte[] pinBytes) throws RemoteException, UserException;

	public byte[] getPublicKeyBytes() throws RemoteException, UserException;

	public void useAsymmetricEncryption() throws RemoteException, UserException;

	public void setSecretKey(byte[] keyBytes) throws RemoteException, UserException;

	// account details

	public byte[] getName() throws RemoteException, UserException;

	public byte[] getAccountNumber() throws RemoteException, UserException;

	public byte[] getExpiryDate() throws RemoteException, UserException;

	public byte[] getSecurityCode() throws RemoteException, UserException;

	public void useSymmetricEncryption() throws RemoteException, UserException;
}
