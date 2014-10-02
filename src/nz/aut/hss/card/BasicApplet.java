/**
   A simple Java Card applet that demonstrates checking a PIN that is
   provided to the applet by a user via a command APDU
   Note: Requires Java Card Development Kit and Ant to be installed.
   Use the following command line statements from the directory that
   contains the file build.xml.
   Build (compile) the applet using:
      ant build-applet
   Then deploy the applet using:
      ant deploy-applet
   Once deployed the APDU script BasicScript.scr can be run:
      ant run-script
   to install and test the applet script via Java Card Development Kit
*/
package basic;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class BasicApplet extends Applet
{
   private OwnerPIN pin;
   private byte[] name, accNum, securityCode, expiryDate, secretCode;
   
   private static final byte PIN_TRIES = 3;
   
   private static final byte APPLET_CLA = (byte)0x80;
   private static final byte SET_PIN = 0x10;
   
   private static final short SW_PIN_FAILED=(short)0x69C0;//error code

   private static final byte[] ACCEPT_MESSAGE//bytes for "PIN Accepted"
      = {0x50,0x49,0x4E,0x20,0x41,0x63,0x63,0x65,0x70,0x74,0x65,0x64};
         
   protected BasicApplet(byte[] nameBytes, byte[] accNumBytes, byte[] securityCodeBytes, byte[] expiryDateBytes, 
				byte[] secretCodeBytes)
   {  super();
      name = nameBytes;
      accNum = accNumBytes;
      securityCode = securityCodeBytes;
      expiryDate = expiryDateBytes;
      secretCode = secretCodeBytes;
      pin = null;
   }
   
   public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
   {  
      // put a NAME in a transient array
      byte[] nameBytes = JCSystem.makeTransientByteArray((short)12,
         JCSystem.CLEAR_ON_RESET);
      nameBytes = {0x5A, 0x6F, 0x65,
			0x20, 0x57, 0x20,
		0x57, 0x61, 0x72, 0x65, 0x6E, 0x6};

      // put an ACCOUNT NUMBER in a transient array
      byte[] accNumBytes = JCSystem.makeTransientByteArray((short)6,
         JCSystem.CLEAR_ON_RESET);
      accNumBytes = {9, 8, 7, 6, 5, 4};
      
      // put a SECURITY CODE in a transient array
      byte[] securityCodeBytes = JCSystem.makeTransientByteArray((short)3,
         JCSystem.CLEAR_ON_RESET);
      securityCodeBytes = {7, 7, 7}
 
      // put an EXPIRYDATE in a transient array
      byte[] expiryDateBytes = JCSystem.makeTransientByteArray((short)5,
         JCSystem.CLEAR_ON_RESET);
      expiryDateBytes = {0, 2, 0X2F, 1, 7}

     // put the SECRETCODE in a transient array
     byte[] secretCodeBytes = JCSystem.makeTransientByteArray((short)5,
         JCSystem.CLEAR_ON_RESET);
      secretCodeBytes = {0x48,0x69,0x20,
		0x4D,0x61,0x72,0x74,0x69,0x6E};

      // create a transient array for the PIN
      //byte[] pinBytes = JCSystem.makeTransientByteArray((short)4,
      //   JCSystem.CLEAR_ON_RESET);


      //create the applet object using the: PIN, ACCOUNT NUMBER AND SECURITY NUMBER as parameters
      HelloWorldApplet applet = new HelloWorldApplet(nameBytes, accNumBytes, securityCodeBytes, expiryDateBytes, secretCodeBytes);
      
      // once all memory successfully allocated for applet then
      // register the applet using aid if it was given as parameter
      byte aidLength = bArray[bOffset];
      if (aidLength == 0)
         applet.register();
      else
         applet.register(bArray, (short)(bOffset+1), aidLength);   
   }
   
   public boolean select()
   {  // perform session specific initializations
      return true;
   }
   
   public void process(APDU apdu) throws ISOException
   {  // get the incoming APDU buffer
      byte[] buffer = apdu.getBuffer();
      // get the CLA but mask out the logical channel information
      byte cla = (byte)(buffer[ISO7816.OFFSET_CLA] & (byte)0xFC);
      // get remaining command APDU header information from buffer
      byte ins = buffer[ISO7816.OFFSET_INS];
      byte p1 = buffer[ISO7816.OFFSET_P1];
      byte p2 = buffer[ISO7816.OFFSET_P2];
      // check whether command APDU is select and if so don't process
      if (cla==ISO7816.CLA_ISO7816 && ins==ISO7816.INS_SELECT)
         return;
      // check whether the CLA is suitable for this applet
      if (cla != APPLET_CLA)
         ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
      // process the instruction
      switch (ins)
      {  case SET_PIN:
            setPin(apdu);
            break;
         default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            break;
      }
   }
   
   public void deselect()
   {  // perform session specific cleanup
      pin.reset(); // if PIN validated then reset the tries
   }

   private void setPin(APDU apdu)
   {
      // get the incoming APDU buffer which holds user PIN attempt
      byte[] buffer = apdu.getBuffer();
      byte pinLength = buffer[ISO7816.OFFSET_LC];
      
      // get the expected incoming data in command APDU optional body
      short count = apdu.setIncomingAndReceive();
      if (count < pinLength)
         ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      else
      {  pin = new OwnerPIN(PIN_TRIES, pinLength);
         pin.update(buffer, ISO7816.OFFSET_CDATA, pinLength);
         
         apdu.setOutgoingLength(messageLength);//set response JCRE mode
         // copy message into apdu buffer and send response
         Util.arrayCopy(ACCEPT_MESSAGE, (short)0, buffer, (short)0,
            messageLength);
         apdu.sendBytes((short)0, messageLength);
         // after all messageLength bytes have been sent the response
         // is appended with the default 9000 status (no error)
      }
   }
}
