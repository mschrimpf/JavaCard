package nz.ac.aut.hss.card.client;

import javacard.security.KeyBuilder;

/**
 * @author Martin Schrimpf
 * @created 10.10.2014
 */
public class KeySpec {
	public static final short EXPONENT_OFFSET = 0;
	public static final short EXPONENT_LENGTH = 3;
	public static final short MODULOS_OFFSET = EXPONENT_OFFSET + EXPONENT_LENGTH;
	public static final short MODULOS_LENGTH = 64;

	public static final short SESSION_KEY_LENGTH_BITS = KeyBuilder.LENGTH_AES_128;
	public static final byte[] SESSION_IV_BYTES = {66, 49, 70, 39, 120, -90, 81, -83, 60, -19, 6, 123,
			53, 91, -80, -89}; // 16 bytes (one block) initialization vector
}
