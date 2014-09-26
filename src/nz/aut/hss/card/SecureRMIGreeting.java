/**
   A JCRMI remote interface that represents a secret message
   @see RemoteGreetingImpl.java
*/
package nz.aut.hss.card;

import java.rmi.Remote;
import java.rmi.RemoteException;
import javacard.framework.UserException;

public interface SecureRMIGreeting extends Remote
{
   public byte[] getGreeting() throws RemoteException, UserException;
   public void setGreeting(byte[] message)
      throws RemoteException, UserException;   
}
