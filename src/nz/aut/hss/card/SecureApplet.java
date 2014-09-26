/**
 A simple Java Card applet that registers a JCRMI remote object
 and uses a SecurityService to handle encryption of the APDU
 Note: Requires Java Card Development Kit and Ant to be installed.
 Use the following command line statements from the directory that
 contains the file build.xml.
 Build (compile) the applet using:
 ant build-applet
 Then deploy the applet using:
 ant deploy-applet
 Finally, the applet is installed using SecureRMIDemoScript script:
 ant run-script
 @author Andrew Ensor
 */
package nz.aut.hss.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.service.Dispatcher;
import javacard.framework.service.RMIService;
import javacard.framework.service.SecurityService;

public class SecureApplet extends Applet {
	// maximum number of incorrect tries before the
	// PIN is blocked
	final static byte PIN_TRY_LIMIT = (byte) 0x03;
	// maximum size PIN
	final static byte MAX_PIN_SIZE = (byte) 0x08;

	private OwnerPIN pin;
	private SecureRMIGreeting remoteObject;
	private Dispatcher dispatcher;

	protected SecureApplet(byte[] bArray, short bOffset, byte bLength) {
		super();

		// allocate all the memory that an applet needs during its lifetime inside the constructor
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

		byte aidLength = bArray[bOffset]; // aid length
		bOffset = (short) (bOffset + aidLength + 1);
		byte cLen = bArray[bOffset]; // info length
		bOffset = (short) (bOffset + cLen + 1);

		// The installation parameters contain the PIN
		// initialization value
		pin.update(bArray, (short) (bOffset + 1), aidLength);

		// once all memory successfully allocated for applet then
		// register the applet using aid if it was given as parameter
		if (aidLength == 0)
			register();
		else
			register(bArray, (short) (bOffset + 1), aidLength);

		// create a SecurityService to handle encryption of APDU
		SecurityService security = new Security();
		// put an initial message "Secure World" in an array
		byte[] initialMessage = {0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
		// create the remote object
		remoteObject = new SecureRMIGreetingImpl(initialMessage, security);
		// allocate an RMI service and dispatcher to process commands
		dispatcher = new Dispatcher((short) 3); // three services added
		dispatcher.addService(security, Dispatcher.PROCESS_INPUT_DATA); // preprocess command APDU
		dispatcher.addService(new RMIService(remoteObject), Dispatcher.PROCESS_COMMAND);
		dispatcher.addService(security, Dispatcher.PROCESS_OUTPUT_DATA); // postprocess response APDU
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		new SecureApplet(bArray, bOffset, bLength);
	}

	public void process(APDU apdu)
			throws ISOException {  // allow dispatcher to process command and prepare response APDU
		dispatcher.process(apdu);
	}
}
