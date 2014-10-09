package nz.ac.aut.hss.card.client;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;

/**
 * @author Martin Schrimpf
 * @created 09.10.2014
 */
public class KeyUtil {
	public static final short EXPONENT_OFFSET = 0, EXPONENT_LENGTH = 3,
			MODULOS_OFFSET = EXPONENT_OFFSET + EXPONENT_LENGTH, MODULOS_LENGTH = 64;

	public static KeyPair createRSAPair() {
		KeyPair keypair = new KeyPair(KeyPair.ALG_RSA, (short) 512);
		keypair.genKeyPair();
		return keypair;
	}

	public static byte[] toBytes(RSAPublicKey publicKey) {
		byte[] bytes = new byte[EXPONENT_LENGTH + MODULOS_LENGTH];
		short length = 0;
		length = publicKey.getExponent(bytes, EXPONENT_OFFSET);
		if (length != EXPONENT_LENGTH) // incorrect length
			ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
		length = publicKey.getModulus(bytes, length);
		if (length != MODULOS_LENGTH)// incorrect length
			ISOException.throwIt(ISO7816.SW_CORRECT_LENGTH_00);
		return bytes;
	}

	public static RSAPublicKey toKey(byte[] bytes) {
		RSAPublicKey key = (RSAPublicKey) KeyBuilder
				.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) (EXPONENT_LENGTH + MODULOS_LENGTH), false);
		key.setExponent(bytes, EXPONENT_OFFSET, EXPONENT_LENGTH);
		key.setModulus(bytes, MODULOS_OFFSET, MODULOS_LENGTH);
		return key;
	}


}
