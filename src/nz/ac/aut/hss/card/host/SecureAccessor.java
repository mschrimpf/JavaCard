package nz.ac.aut.hss.card.host;

import com.sun.javacard.clientlib.CardAccessor;
import nz.ac.aut.hss.card.client.KeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;

/**
 * A CardAccessor that handles encryption and decryption of APDU that
 * are transmitted as part of JCRMI (whose SW1 and SW2 bytes are
 * placed at start of response).
 * Uses the Decorator design pattern to implement secure APDU access
 * @see nz.ac.aut.hss.card.host.SecureHost
 */
public class SecureAccessor implements CardAccessor {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String RSA_ALGORITHM = "RSA/NONE/PKCS1Padding";
	private static final String AES_ALGORITHM = "AES/CBC/NoPadding";

	private CardAccessor ca;
	private SecretKey sessionKey;
	private IvParameterSpec initVector;
	private Cipher cipher; // AES cipher in CBC mode with no padding
	private static final byte BLOCK_SIZE = 16; // 16 byte cipher blocks
	private static final byte CLA_SECURITY_BITS_MASK = (byte) 0x0C;
	private static final byte CLA_ISO7816 = (byte) 0x00;
	private static final byte INS_SELECT = (byte) 0xA4;
	private static final byte OFFSET_CLA = (byte) 0;
	private static final byte OFFSET_INS = (byte) 1;
	private static final byte OFFSET_LC = (byte) 4;
	private static final byte OFFSET_CDATA = (byte) 5;
	private static final byte OFFSET_SW1 = (byte) 0; // JCRMI position
	private static final byte OFFSET_SW2 = (byte) 1; // JCRMI position
	private static final byte OFFSET_RDATA = (byte) 2;
	private static final boolean DISPLAY_APDU = true; // use for debug
	private PublicKey publicKey;
	private boolean splitEncryption;

	public SecureAccessor(CardAccessor ca) {
		this.ca = ca;
		initVector = new IvParameterSpec(KeySpec.SESSION_IV_BYTES);
	}

	public void setSessionKey(SecretKey key) {
		this.sessionKey = key;
		try {
			cipher = Cipher.getInstance(AES_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Encryption algorithm not available: " + e);
		} catch (NoSuchPaddingException e) {
			System.err.println("Padding scheme not available: " + e);
		}
		this.publicKey = null;
		this.splitEncryption = false;
	}

	public void setPublicKey(final PublicKey publicKey) throws InvalidKeyException {
		if (publicKey == null)
			throw new IllegalArgumentException("publicKey is null");
		this.publicKey = publicKey;
		try {
			cipher = Cipher.getInstance(RSA_ALGORITHM);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Encryption algorithm not available: " + e);
		} catch (NoSuchPaddingException e) {
			System.err.println("Padding scheme not available: " + e);
		}
		this.sessionKey = null;
		this.splitEncryption = true;
	}

	public byte[] exchangeAPDU(byte[] sendData) throws IOException {
		// get the CLA but mask out the logical channel information
		byte cla = (byte) (sendData[OFFSET_CLA] & (byte) 0xFC);
		byte ins = sendData[OFFSET_INS];
		// check if APDU is for selecting applet
		if ((cla == CLA_ISO7816 && ins == INS_SELECT) || cipher == null) {
			return ca.exchangeAPDU(sendData);
		} else {  // encrypt the data field in the command APDU
			byte[] encryptedCommand = encrypt(sendData);
			byte[] encryptedResponse = ca.exchangeAPDU(encryptedCommand);
			return decrypt(encryptedResponse);
		}
	}

	private byte[] encrypt(final byte[] sendData) throws IOException {
		if (DISPLAY_APDU) {
			System.out.println("PLAINTEXT COMMAND APDU:");
			for (final byte aSendData : sendData) System.out.print(" " + Integer.toHexString(aSendData & 0xFF));
			System.out.println();
		}
		byte lc = sendData[OFFSET_LC];
		byte[] plaintext = pad(sendData, OFFSET_CDATA, lc);
		initCipher(Cipher.ENCRYPT_MODE);
		byte[] ciphertext;
		try {
			if (splitEncryption) {
				byte[][] plaintexts = split(plaintext, 32);
				byte[][] ciphertexts = applyCipher(plaintexts, cipher);
				ciphertext = merge(ciphertexts);
			} else {
				ciphertext = cipher.doFinal(plaintext);
			}
		} catch (IllegalBlockSizeException e) {
			throw new IOException("Illegal padding in encryption", e);
		} catch (BadPaddingException e) {
			throw new IOException("Bad padding in encryption", e);
		}
		if (ciphertext.length > 255)
			throw new IOException("Command APDU too long");
		// copy the ciphertext into encryptedCommand
		byte[] encryptedCommand = new byte[OFFSET_CDATA + ciphertext.length + 1];
		System.arraycopy(sendData, 0, encryptedCommand, 0, OFFSET_CDATA - 1);
		encryptedCommand[OFFSET_CLA] |= CLA_SECURITY_BITS_MASK;
		encryptedCommand[OFFSET_LC] = (byte) ciphertext.length;
		System.arraycopy(ciphertext, 0, encryptedCommand, OFFSET_CDATA, ciphertext.length);
		encryptedCommand[encryptedCommand.length - 1] = sendData[sendData.length - 1];
		// send the command APDU and obtain the response APDU
		if (DISPLAY_APDU) {
			System.out.println("CIPHERTEXT COMMAND APDU:");
			for (int i = 0; i < encryptedCommand.length; i++)
				System.out.print(" " + Integer.toHexString
						(encryptedCommand[i] & 0xFF));
			System.out.println();
		}
		return encryptedCommand;
	}

	private byte[] merge(final byte[][] bytes) {
		int length = 0;
		for (final byte[] aByte : bytes) {
			length += aByte.length;
		}
		byte[] result = new byte[length];

		int offset = 0;
		for (final byte[] aByte : bytes) {
			System.arraycopy(aByte, 0, result, offset, aByte.length);
			offset += aByte.length;
		}
		return result;
	}

	private byte[][] applyCipher(final byte[][] plaintexts, final Cipher cipher)
			throws BadPaddingException, IllegalBlockSizeException {
		byte[][] ciphertexts = new byte[plaintexts.length][];

		final int keySize = ((RSAPublicKey) publicKey).getModulus().bitLength();

		for (int i = 0; i < ciphertexts.length; i++) {
			final int plaintextBitLength = plaintexts[i].length * 8;
			if (plaintextBitLength < keySize) {
//					throw new IllegalArgumentException(
				System.err.println(
						"Data is too big (" + plaintextBitLength + " bits > " + keySize + ")");
			}
			ciphertexts[i] = cipher.doFinal(plaintexts[i]);
		}
		return ciphertexts;
	}

	private byte[][] split(final byte[] bytes, int amount) {
		byte[][] result = new byte[amount][];
		int eachLength = bytes.length / amount;
		int offset = 0;
		for (int i = 0; i < result.length; i++) {
			int length;
			if (i < result.length - 1) { // pre-last
				length = eachLength;
			} else { // last
				length = bytes.length - offset;
			}
			result[i] = new byte[length];
			System.arraycopy(bytes, offset, result[i], 0, length);

			offset += length;
		}
		return result;
	}

	private byte[] decrypt(final byte[] encryptedResponse) throws IOException {
		if (DISPLAY_APDU) {
			System.out.println("CIPHERTEXT RESPONSE APDU:");
			for (int i = 0; i < encryptedResponse.length; i++)
				System.out.print(" " + Integer.toHexString
						(encryptedResponse[i] & 0xFF));
			System.out.println();
		}
		// decrypt the data field in response APDU
		// note that JCRMI puts SW1 and SW2 first in the response
		// and not as a trailer (unlike a standard response APDU)
		if ((encryptedResponse.length - 2) % BLOCK_SIZE != 0) {
			throw new IOException("Illegal block size in response");
		}
		if (publicKey == null) { // only for symmetric encryption
			initCipher(Cipher.DECRYPT_MODE);
		}
		byte[] deciphertext = null;
		try {
			deciphertext = cipher.doFinal(encryptedResponse, OFFSET_RDATA, encryptedResponse.length - 2);
		} catch (IllegalBlockSizeException e) {
			System.err.println("Illegal padding in decryption: " + e);
		} catch (BadPaddingException e) {
			System.err.println("Bad padding in decryption: " + e);
		}
		if (deciphertext.length == 0)
			throw new IllegalStateException("deciphertext length is 0");
		byte numPadding = deciphertext[deciphertext.length - 1];
		int unpaddedLength = deciphertext.length - numPadding;
		byte[] decryptedResponse
				= new byte[OFFSET_RDATA + unpaddedLength];
		decryptedResponse[OFFSET_SW1] = encryptedResponse[OFFSET_SW1];
		decryptedResponse[OFFSET_SW2] = encryptedResponse[OFFSET_SW2];
		System.arraycopy(deciphertext, 0, decryptedResponse,
				OFFSET_RDATA, unpaddedLength);
		if (DISPLAY_APDU) {
			System.out.println("DECIPHERTEXT RESPONSE APDU:");
			for (int i = 0; i < decryptedResponse.length; i++)
				System.out.print(" " + Integer.toHexString
						(decryptedResponse[i] & 0xFF));
			System.out.println();
		}
		return decryptedResponse;
	}

	private void initCipher(final int mode) {
		try {
			if (publicKey != null) {
				cipher.init(mode, publicKey);
			} else {
				cipher.init(mode, sessionKey, initVector);
			}
		} catch (InvalidKeyException e) {
			System.err.println("Invalid key for en-/decryption: " + e);
		} catch (InvalidAlgorithmParameterException e) {
			System.err.println("Invalid IV in en-/decryption: " + e);
		}
	}

	public void closeCard() throws Exception {
		ca.closeCard();
	}

	// helper method which pads the specified array segment to have
	// blocks of length BLOCK_SIZE bytes as per a PKCS#5 padding scheme
	// Note that padding bytes always each give number of padded bytes
	private byte[] pad(byte[] unpadded, int start, int unpaddedLength) {
		int numBlocks = (unpaddedLength + BLOCK_SIZE) / BLOCK_SIZE;
		int paddedLength = numBlocks * BLOCK_SIZE;
		byte[] padded = new byte[paddedLength];
		System.arraycopy(unpadded, start, padded, 0, unpaddedLength);
		byte numPadding = (byte) (paddedLength - unpaddedLength);
		for (int i = unpaddedLength; i < paddedLength; i++)
			padded[i] = numPadding;
		return padded;
	}

}
