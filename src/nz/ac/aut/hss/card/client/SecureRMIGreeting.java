/**
   A JCRMI remote interface that represents a secret message
   @see RemoteGreetingImpl.java
*/
package nz.ac.aut.hss.card.client;

import javacard.framework.UserException;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface SecureRMIGreeting extends Remote
{
   public byte[] getGreeting() throws RemoteException, UserException;
   public void setGreeting(byte[] message)
      throws RemoteException, UserException;   
}
