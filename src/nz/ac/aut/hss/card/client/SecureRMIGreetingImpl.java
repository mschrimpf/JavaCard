/**
 A class that implements a JCRMI remote object holding a message
 @author Andrew Ensor
 */
package nz.ac.aut.hss.card.client;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.UserException;
import javacard.framework.Util;
import javacard.framework.service.CardRemoteObject;
import javacard.framework.service.SecurityService;

import java.rmi.RemoteException;

public class SecureRMIGreetingImpl implements SecureRMIGreeting {
	private byte[] message;
	private SecurityService security;
	private static final short REQUEST_DENIED = (short) 0x6003;

	public SecureRMIGreetingImpl(byte[] message, SecurityService security) {
		this.message = message;
		this.security = security;
		CardRemoteObject.export(this); // export this remote object
	}

	public byte[] getGreeting()
			throws RemoteException, UserException {  // check the communication is confidential (encrypted)
		if (!security.isCommandSecure(SecurityService.PROPERTY_OUTPUT_CONFIDENTIALITY))
			UserException.throwIt(REQUEST_DENIED);
		return message;
	}

	public void setGreeting(byte[] message)
			throws RemoteException, UserException {  // check the communication is confidential (encrypted)
		if (!security.isCommandSecure(SecurityService.PROPERTY_INPUT_CONFIDENTIALITY))
			UserException.throwIt(REQUEST_DENIED);
		// copy transient message parameter to persistent message field
		JCSystem.beginTransaction();
		this.message = new byte[message.length]; // new persistent array
		Util.arrayCopyNonAtomic(message, (short) 0, this.message,
				(short) 0, (short) message.length);
		JCSystem.commitTransaction();
		try {
			JCSystem.requestObjectDeletion();//request garbage collection
		} catch (SystemException ignore) {
		} // ignore as no object deletion mechanism available
	}
}
