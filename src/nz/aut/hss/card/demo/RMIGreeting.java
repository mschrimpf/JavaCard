package nz.aut.hss.card.demo;

import java.rmi.Remote;
import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 24.09.2014
 */
public interface RMIGreeting extends Remote {
	public byte[] getGreeting() throws RemoteException;
	public void setGreeting(byte[] message) throws RemoteException;
}
