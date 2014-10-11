package nz.ac.aut.hss.card.host;

import nz.ac.aut.hss.card.client.KeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * @author Martin Schrimpf
 * @created 10.10.2014
 */
public class KeyUtil {

	// executed on host
	public static PublicKey toKey(byte[] bytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] exponentBytes = new byte[KeySpec.EXPONENT_LENGTH];
		System.arraycopy(bytes, KeySpec.EXPONENT_OFFSET, exponentBytes, 0, KeySpec.EXPONENT_LENGTH);
		byte[] modulusBytes = new byte[KeySpec.MODULOS_LENGTH];
		System.arraycopy(bytes, KeySpec.MODULOS_OFFSET, modulusBytes, 0, KeySpec.MODULOS_LENGTH);
		BigInteger exponent = new BigInteger(exponentBytes);
		BigInteger modulus = new BigInteger(modulusBytes);
		RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		return factory.generatePublic(spec);
	}

	public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keySize);
		return keyGen.generateKey();
	}
}
