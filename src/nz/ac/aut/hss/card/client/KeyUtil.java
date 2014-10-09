package nz.ac.aut.hss.card.client;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;

/**
 * @author Martin Schrimpf
 * @created 09.10.2014
 */
public class KeyUtil {

	public static KeyPair createRSAPair() {
		KeyPair keypair = new KeyPair(KeyPair.ALG_RSA, (short) 512);
		keypair.genKeyPair();
		return keypair;
	}

	// executed on card
	public static byte[] toBytes(RSAPublicKey publicKey) {
		byte[] bytes = new byte[KeySpec.EXPONENT_LENGTH + KeySpec.MODULOS_LENGTH];
		short length = 0;
		length = publicKey.getExponent(bytes, KeySpec.EXPONENT_OFFSET);
		if (length != KeySpec.EXPONENT_LENGTH) // incorrect length
			ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
		length = publicKey.getModulus(bytes, length);
		if (length != KeySpec.MODULOS_LENGTH)// incorrect length
			ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
		return bytes;
	}
}
