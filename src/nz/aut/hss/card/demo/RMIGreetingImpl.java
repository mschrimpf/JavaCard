package nz.aut.hss.card.demo;

import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.framework.service.CardRemoteObject;

import java.rmi.RemoteException;

/**
 * @author Martin Schrimpf
 * @created 24.09.2014
 */
public class RMIGreetingImpl implements RMIGreeting {
	private byte[] message;

	public RMIGreetingImpl(final byte[] message) {
		this.message = message;
		CardRemoteObject.export(this);
	}

	@Override
	public byte[] getGreeting() throws RemoteException {
		return message;
	}

	@Override
	public void setGreeting(final byte[] message) throws RemoteException {
		JCSystem.beginTransaction();
		this.message = new byte[message.length];
		Util.arrayCopyNonAtomic(message, (short) 0, this.message, (short) 0, (short) message.length);
		JCSystem.commitTransaction();
		try {
			JCSystem.requestObjectDeletion();
		} catch (SystemException ignore) {
		}
	}
}
