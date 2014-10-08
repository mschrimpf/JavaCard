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
package nz.ac.aut.hss.card.client;

import javacard.framework.*;
import javacard.framework.service.Dispatcher;
import javacard.framework.service.RMIService;
import javacard.security.PublicKey;


/**
 * @see <a href="http://stackoverflow.com/questions/21284830/working-with-java-card-wallet">Stackoverflow Wallet</a>
 */
public class SecureApplet extends Applet {
	private static final byte APPLET_CLA = (byte) 0x80;
	private static final byte SET_PIN = (byte) 0xAA;

	/** maximum number of incorrect tries before the PIN is blocked */
	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	/** maximum size PIN */
	private final static byte MAX_PIN_SIZE = (byte) 0x08;

	private final Dispatcher dispatcher;
	private OwnerPIN pin;

	protected SecureApplet() {
		super();

		// create a SecurityService to handle encryption of APDU
		Security security = new Security();
		// create the remote object
		final PublicKey publicKey = null;
		final RemoteObject remoteObject = new RemoteObjectImpl(security, publicKey, this);
//		// allocate an RMI service and dispatcher to process commands
		dispatcher = new Dispatcher((short) 3); // three services added
		dispatcher.addService(security, Dispatcher.PROCESS_INPUT_DATA); // preprocess command APDU
		dispatcher.addService(new RMIService(remoteObject), Dispatcher.PROCESS_COMMAND);
		dispatcher.addService(security, Dispatcher.PROCESS_OUTPUT_DATA); // postprocess response APDU
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
		SecureApplet applet = new SecureApplet();

		// once all memory successfully allocated for applet then
		// register the applet using aid if it was given as parameter
		byte aidLength = bArray[bOffset];
		if (aidLength == 0)
			applet.register();
		else
			applet.register(bArray, (short) (bOffset + 1), aidLength);
	}

	public void process(APDU apdu)
			throws ISOException {
		// get the incoming APDU buffer
		byte[] buffer = apdu.getBuffer();
		// get the CLA but mask out the logical channel information
		byte cla = (byte) (buffer[ISO7816.OFFSET_CLA] & (byte) 0xFC);
		// get remaining command APDU header information from buffer
		byte ins = buffer[ISO7816.OFFSET_INS];
		// check whether command APDU is select and if so don't process
		if (cla == ISO7816.CLA_ISO7816 && ins == ISO7816.INS_SELECT)
			return;
		// check whether the CLA is suitable for this applet
		if (cla != APPLET_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		// process the instruction
		switch (ins) {
			case SET_PIN:
				setPin(apdu);
				break;
			default:
				// allow dispatcher to process command and prepare response APDU
				dispatcher.process(apdu);
				break;
		}
	}

	public boolean isPinValidated() {
		return pin.isValidated();
	}

	private void setPin(final APDU apdu) {
		if (pin != null) // already set
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

            
          byte[] buffer = apdu.getBuffer();
          byte pinLength = buffer[ISO7816.OFFSET_LC];
		// allocate all the memory that an applet needs during its lifetime inside the constructor
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        pin.update(buffer, ISO7816.OFFSET_CDATA, pinLength);
	}
    
	public boolean checkPIN(final byte[] pinBytes, final short offset, final byte length) {
		return pin.check(pinBytes, offset, length);
	}

	public short getPINTriesRemaining() {
		return pin.getTriesRemaining();
	}
}
