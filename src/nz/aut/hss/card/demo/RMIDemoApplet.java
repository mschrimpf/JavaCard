package nz.aut.hss.card.demo;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.service.Dispatcher;
import javacard.framework.service.RMIService;

/**
 * @author Martin Schrimpf
 * @created 24.09.2014
 */
public class RMIDemoApplet extends Applet {
	private Dispatcher dispatcher;

	protected RMIDemoApplet() {
		super();
		byte[] initialMessage = "Hello World".getBytes(); // {0x48, 0x65, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64}
		final RMIGreeting remoteObject = new RMIGreetingImpl(initialMessage);
		dispatcher = new Dispatcher((short) 1);
		dispatcher.addService(new RMIService(remoteObject), Dispatcher.PROCESS_COMMAND);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		RMIDemoApplet applet = new RMIDemoApplet();
		byte aidLength = bArray[bOffset];
		if (aidLength == 0)
			applet.register();
		else
			applet.register(bArray, (short) (bOffset + 1), aidLength);
	}

	@Override
	public void process(final APDU apdu) throws ISOException {
		dispatcher.process(apdu);
	}
}
