package nz.aut.hss.card.simulation;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import nz.aut.hss.card.demo.RMIDemoApplet;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * @author Martin Schrimpf
 * @created 24.09.2014
 */
public class RemoteSimulationDemo {
	private static final String
			LOCAL = "0",
			REMOTE = "1",
			LOCAL_WITH_TRANSMIT = "2";

	public static void main(String[] args) {
		System.setProperty("com.licel.jcardsim.terminal.type", LOCAL_WITH_TRANSMIT);
		CAD cad = new CAD(System.getProperties());
		JavaxSmartCardInterface simulator = (JavaxSmartCardInterface) cad.getCardInterface();
		byte[] appletAIDBytes = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9};
		AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);
		simulator.installApplet(appletAID, RMIDemoApplet.class);
		simulator.selectApplet(appletAID);
		// test NOP
		ResponseAPDU response = simulator.transmitCommand(new CommandAPDU(0x01, 0x02, 0x00, 0x00));
		System.out.println(response.getSW());
		// test hello world from card
		response = simulator.transmitCommand(new CommandAPDU(0x01, 0x01, 0x00, 0x00));
		System.out.println(response.getSW());
		System.out.println(new String(response.getData()));
		// test echo
		response = simulator
				.transmitCommand(new CommandAPDU(0x01, 0x01, 0x01, 0x00, ("Hello javacard world !").getBytes()));
		System.out.println(response.getSW());
		System.out.println(new String(response.getData()));
	}
}
