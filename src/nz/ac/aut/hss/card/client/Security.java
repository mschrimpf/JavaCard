/**
 A SecurityService that handles encryption and decryption of APDU
 Note that only the commandProperties have been implemented below
 @see SecureRMIDemoApplet
 */
package nz.ac.aut.hss.card.client;

import javacard.framework.*;
import javacard.framework.service.BasicService;
import javacard.framework.service.SecurityService;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

public class Security extends BasicService implements SecurityService {
	private static final short ENCRYPT_NONE = 0,
			ASYMMETRIC_REQUEST = 1, ENCRYPT_ASYMMETRIC = 2,
			SYMMETRIC_REQUEST = 3, ENCRYPT_SYMMETRIC = 4;
	private short mode;

	private boolean appProviderAuthenticated, cardIssuerAuthenticated,
			cardHolderAuthenticated;
	private byte sessionProperties; // bits give session secure props
	private byte commandProperties; // bits give command secure props
	private byte[] tempTransientArray; //may be reused so use with care
	private static final byte BLOCK_SIZE = 16; // 16 byte decryptCipher blocks
	private static final byte CLA_SECURITY_BITS_MASK = (byte) 0x0C;
	private static final byte OFFSET_OUT_LA = (byte) 4;
	private static final byte OFFSET_OUT_RDATA = (byte) 5;

	private final RSAPrivateKey privateKey;
	private AESKey key;
	private Cipher encryptCipher, decryptCipher;

	public Security(final RSAPrivateKey privateKey) {
		super();
		if (privateKey == null)
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		this.privateKey = privateKey;
		resetSecuritySettings();
		// create a transient array of initial length 10 bytes
		tempTransientArray = JCSystem.makeTransientByteArray((short) 10, JCSystem.CLEAR_ON_DESELECT);
		key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeySpec.SESSION_KEY_LENGTH_BITS, false);
		encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		mode = ENCRYPT_NONE;
	}

	public void setSessionKey(final byte[] keyBytes) throws CryptoException {
		if (keyBytes.length != KeySpec.SESSION_KEY_LENGTH_BITS / 8)
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		if (key.isInitialized()) // already initialized
			CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);

		key.setKey(keyBytes, (short) 0);
	}

	public void useSymmetric() {
		mode = SYMMETRIC_REQUEST;
	}

	public void usePrivateKey() {
		decryptCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		decryptCipher.init(privateKey, Cipher.MODE_DECRYPT); // TODO init in decrypt method
		mode = ASYMMETRIC_REQUEST;
	}

	// helper method that resets the security settings
	private void resetSecuritySettings() {
		appProviderAuthenticated = false;
		cardIssuerAuthenticated = false;
		cardHolderAuthenticated = false;
		sessionProperties = 0;
		commandProperties = 0;
	}

	// overridden method of BasicService that performs encryption
	// returns true if no more postprocessing should be performed
	// by any other Service that has been added to handles the APDU
	public boolean processDataOut(APDU apdu) {
		if (selectingApplet())
			return false; //allow other Services to postprocess if needed
		if (mode == ENCRYPT_NONE) {
			return false;
		}
		if (mode == SYMMETRIC_REQUEST) {
			mode = ENCRYPT_SYMMETRIC;
			return false;
		}
		if(mode == ASYMMETRIC_REQUEST) {
			mode = ENCRYPT_ASYMMETRIC;
			return false;
		}

		// get outgoing APDU buffer (CLA,INS,SW1,SW2,Le,data field)
		byte[] buffer = apdu.getBuffer();

		// encrypt the data field in response APDU
		byte unpaddedLength = (byte) (buffer[OFFSET_OUT_LA] & 0xFF);
		// pad the buffer segment to have blocks of length BLOCK_SIZE
		// bytes as per PKCS#5 padding scheme where the padding bytes
		// always each give the number of padded bytes
		short numBlocks = (short) ((short) (unpaddedLength + BLOCK_SIZE)
				/ BLOCK_SIZE);
		short paddedLength = (short) (numBlocks * BLOCK_SIZE);
		byte[] padded = getTransientArray(paddedLength);
		Util.arrayCopyNonAtomic(buffer, OFFSET_OUT_RDATA, padded, (short) 0, unpaddedLength);
		byte numPadding = (byte) (paddedLength - unpaddedLength);
		for (short i = unpaddedLength; i < paddedLength; i++)
			padded[i] = numPadding;
		if ((short) (OFFSET_OUT_RDATA - 1 + paddedLength) >
				buffer.length) { // outgoing buffer can not accommodate the padding
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		if(mode == ENCRYPT_SYMMETRIC) {
			encryptCipher.init(key, Cipher.MODE_ENCRYPT, KeySpec.SESSION_IV_BYTES, (short) 0,
					(short) KeySpec.SESSION_IV_BYTES.length);
		} else if(mode == ENCRYPT_ASYMMETRIC) {
			encryptCipher.init(privateKey, Cipher.MODE_ENCRYPT);
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		encryptCipher.doFinal(padded, (short) 0, paddedLength, buffer, OFFSET_OUT_RDATA);
		buffer[OFFSET_OUT_LA] = (byte) paddedLength;
        
		return true; // don't allow any other postprocessing
	}

	// overridden method of BasicService that performs decryption
	// returns true if no more preprocessing should be performed
	// by any other Service that has been added to handles the APDU
	public boolean processDataIn(APDU apdu) {
		if (selectingApplet()) {  // APDU is for selecting applet so clear security settings
			resetSecuritySettings();
			return false; // allow other Services to preprocess if needed
		}
        
		if (!apdu.isSecureMessagingCLA()) {  // APDU CLA byte does not indicate secure messaging
			// clear the appropriate command security properties
			commandProperties &=
					~(SecurityService.PROPERTY_INPUT_CONFIDENTIALITY |
							SecurityService.PROPERTY_OUTPUT_CONFIDENTIALITY);
			return false; // allow other Services to preprocess if needed
		}
		if (mode == ENCRYPT_NONE) { // not initialized
			return false;
		}
		if (mode == SYMMETRIC_REQUEST) {
			mode = ENCRYPT_SYMMETRIC;
			return false;
		}
		if(mode == ASYMMETRIC_REQUEST) {
			mode = ENCRYPT_ASYMMETRIC;
			return false;
		}

		// set the appropriate command security properties
		commandProperties |=
				(SecurityService.PROPERTY_INPUT_CONFIDENTIALITY |
						SecurityService.PROPERTY_OUTPUT_CONFIDENTIALITY);
                        
        byte[] buffer = apdu.getBuffer();
		byte lc = buffer[ISO7816.OFFSET_LC]; // padded length
		byte le = buffer[(short) (ISO7816.OFFSET_LC + lc + 1)];
		// decrypt the data field in the command APDU
		if (lc % BLOCK_SIZE != 0)
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		byte[] deciphertext = getTransientArray(lc);
		if(mode == ENCRYPT_SYMMETRIC) {
			decryptCipher.init(key, Cipher.MODE_DECRYPT, KeySpec.SESSION_IV_BYTES, (short) 0,
					(short) KeySpec.SESSION_IV_BYTES.length);
		} else if(mode == ENCRYPT_ASYMMETRIC) {
			decryptCipher.init(privateKey, Cipher.MODE_DECRYPT);
		} else {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
        decryptCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, lc, deciphertext,(short) 0);
        if(Authenticator.checkHash(deciphertext)){
			cardHolderAuthenticated=true;
		}
		byte numPadding = deciphertext[(short) (lc - 1)];
		byte onemorenumPadding = (byte)((short) (numPadding+1));
		byte unpaddedLength = (byte) (lc - numPadding);
		byte onelessunpaddedLength = (byte) ((short)(lc-onemorenumPadding));
		
        
		Util.arrayCopyNonAtomic(deciphertext, (short) 0,
				buffer, ISO7816.OFFSET_CDATA, onelessunpaddedLength);
        buffer[ISO7816.OFFSET_LC] = onelessunpaddedLength;
		// buffer[(short) (ISO7816.OFFSET_LC + unpaddedLength + 1)] = le;
		buffer[(short) (ISO7816.OFFSET_LC + onelessunpaddedLength + 1)] = le;
		// reset the CLA security bits
		buffer[ISO7816.OFFSET_CLA] &= ~CLA_SECURITY_BITS_MASK;
		for (short i = (short) (ISO7816.OFFSET_LC + onelessunpaddedLength + 2); i < buffer.length; i++){
			buffer[i] = 0;
        }
		return true; // don't allow any other preprocessing
	}
    
    // private boolean checkHash(byte[] data){
        // // System.out.println("checking... ");
                // // int j = 0;
        // // for(byte b : data){
            // // System.out.println(":( " + j + ": " + b);
            // // j++;
         // // }      
            // //******************CHECK HASH******************
        // //find length of body of message (short and byte value)
        // byte bytelength = data[OFFSET_LC];
        // short length = (short)bytelength;
        // // System.out.println("length is " + length);
        // //put body of buffer into its own byte[]
        // byte[] bodybuffer = new byte[((short)(length))];
        // System.arraycopy(data, OFFSET_CDATA                                                                                                                                                                                                                                                                                  , bodybuffer,
				// (short) 0, (short)(length));
          // // int i = 0;
        // // for(byte b : data){
            // // System.out.println(":" + i + ": " + b);
            // // i++;
         // // }   
         // byte hash = getHash(bodybuffer, (short)(length-1));
         // // System.out.println("Signature x: " + hash  + ", hash: " + bodybuffer[bodybuffer.length-1]);
         // return hash == bodybuffer[bodybuffer.length-1];
         
        // if(!Authenticator.checkHash(bodybuffer)){
            // CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        // }
        // cardHolderAuthenticated = Authenticator.checkHash(bodybuffer);
        // setAuthentication(true);

    // }

        // private byte[] removeHash(byte[] data, byte lc){
        // byte newlc = (byte)((short)(lc-1));
        // data[ISO7816.OFFSET_LC] = newlc;
        // byte[] buffer = getTransientArray((short)(data.length-1));
		// byte numPadding = data[(short) (ISO7816.OFFSET_LC + lc)];
        // //get lc value and change it
        // //create new array with 1 less length
        // //remove hash
        // //  find padding number
        // //  find index of hash using padding number
        // //copy bytes 0-4 (using new lc value)
        // //copy bytes 5-one below hash index
        // //copy byte one after hash index-length
        
        		// // get the incoming APDU buffer
		// byte[] originalbuffer = apdu.getBuffer();
		// byte originallc = originalbuffer[ISO7816.OFFSET_LC]; // padded length
        // byte lc = (byte) (short) (originallc-1);
		// byte le = originalbuffer[(short) (ISO7816.OFFSET_LC + lc + 1)];
        // originalbuffer[ISO7816.OFFSET_LC] = lc;
        // byte removeIndex = (byte)((short)(originalbuffer.length - (short) numPadding - 1));
        // byte end = (byte)(short)(removeIndex-OFFSET_OUT_RDATA);
        // byte[] buffer = getTransientArray((short)(originalbuffer.length-1));
		// Util.arrayCopyNonAtomic(originalbuffer, (short) 0,
				// buffer, (short) 0, OFFSET_OUT_RDATA);
        // Util.arrayCopyNonAtomic(originalbuffer, OFFSET_OUT_RDATA,
				// buffer, (short) 0, end);        
		// // decrypt the data field in the command APDU
		// if (lc % BLOCK_SIZE != 0)
			// CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		// byte[] deciphertext = getTransientArray(lc);
		// if(mode == ENCRYPT_SYMMETRIC) {
			// decryptCipher.init(key, Cipher.MODE_DECRYPT, KeySpec.SESSION_IV_BYTES, (short) 0,
					// (short) KeySpec.SESSION_IV_BYTES.length);
		// } else if(mode == ENCRYPT_ASYMMETRIC) {
			// decryptCipher.init(privateKey, Cipher.MODE_DECRYPT);
		// } else {
			// ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		// }
		// decryptCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, lc, deciphertext,
				// (short) 0);
		// // byte numPadding = deciphertext[(short) (lc - 1)];
		// byte unpaddedLength = (byte) (lc - numPadding);
		// Util.arrayCopyNonAtomic(deciphertext, (short) 0,
				// buffer, ISO7816.OFFSET_CDATA, unpaddedLength);
		// buffer[ISO7816.OFFSET_LC] = unpaddedLength;
		// buffer[(short) (ISO7816.OFFSET_LC + unpaddedLength + 1)] = le;
		// // reset the CLA security bits
		// buffer[ISO7816.OFFSET_CLA] &= ~CLA_SECURITY_BITS_MASK;
    // }

	// returns whether specified principal (APP_PROVIDER, CARD_ISSUER,
	// or CARDHOLDER) is currently authenticated
	public boolean isAuthenticated(short principal) {
		switch (principal) {
			case PRINCIPAL_APP_PROVIDER:
				return appProviderAuthenticated;
			case PRINCIPAL_CARD_ISSUER:
				return cardIssuerAuthenticated;
			case PRINCIPAL_CARDHOLDER:
				return cardHolderAuthenticated;
			default:
				return false; // unknown principal
		}
	}

	// returns whether a channel has been established for this session
	// between the card and host that has the given security properties
	// (INPUT_CONFIDENTIALITY, INPUT_INTEGRITY, OUTPUT_CONFIDENTIALITY,
	// OUTPUT_INTEGRITY)
	public boolean isChannelSecure(byte properties) {
		return (sessionProperties & properties) != 0;
	}

	// returns whether a channel has been established for this command
	// between the card and host that has the given security properties
	// (INPUT_CONFIDENTIALITY, INPUT_INTEGRITY, OUTPUT_CONFIDENTIALITY,
	// OUTPUT_INTEGRITY)
	public boolean isCommandSecure(byte properties) {
		return (commandProperties & properties) != 0;
	}

	// utility method that returns a temporary transient byte array
	// Note this method tries to conserve the amount of smart card
	// RAM that is used (as its VERY scarce) so reuses the same array
	// whenever possible
	private byte[] getTransientArray(short minSize) {
		if (tempTransientArray.length < minSize) {  // try to allocate a larger transient array, note that this
			// might fail if there is not sufficient RAM available
			tempTransientArray = JCSystem.makeTransientByteArray(minSize,
					JCSystem.CLEAR_ON_DESELECT);
		}
		return tempTransientArray;
	}

	public void clearKey() {
		key.clearKey();
	}
}
