package nz.ac.aut.hss.card.client;

/**
 * @author Martin Schrimpf
 * @created 09.10.2014
 */
public class Authenticator {
	private static byte getHash(byte[] message, short length) {
		byte result = message[0];
		for (short i = 1; i < length; i++) {
			result ^= message[i];
		}
		return result;
	}

	public static byte[] appendHash(byte[] originalmessage) {
		byte[] buffer = new byte[(short) (originalmessage.length + (short) 1)];
		for (short i = 0; i < originalmessage.length; i++) {
			buffer[i] = originalmessage[i];
		}
		byte hash = getHash(originalmessage, (short) originalmessage.length);
		buffer[originalmessage.length] = hash;
		return buffer;
	}

	private static byte recalculateHash(byte[] message) {
		return getHash(message, (short) (message.length - 1));
	}

	public static boolean checkHash(byte[] message) {
		return message[(short) (message.length - 1)] == recalculateHash(message);
	}

	public static byte[] removeHash(final byte[] message) {
		byte[] buffer = new byte[(short) (message.length - 1)];
		for (short i = 0; i < buffer.length; i++) {
			buffer[i] = message[i];
		}
		return buffer;
	}
}
