/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package classicapplet1;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

/**
 *
 * @author mohamed
 */
public class Java_card_applet extends Applet {

    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte APPLET_CLA = (byte) 0xB0;
    final static byte VERIFY = (byte) 0x20;
    final static byte GET_DATA_1 = (byte) 0x30;
    final static byte GET_DATA_2 = (byte) 0x40;
    final static byte GET_DATA_3 = (byte) 0x50;
    final static byte SET_DATA_1 = (byte) 0x31;
    final static byte SET_DATA_2 = (byte) 0x41;
    final static byte SET_DATA_3 = (byte) 0x51;
    final static byte GENERATE_RSA_KEY_PAIR = (byte) 0x55;
    private static final boolean NO_EXTERNAL_ACCESS = false;
    final static byte UNBLOCK = (byte) 0x22;
    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;
    final static short SW_VERIFICATION_FAILED = 0x6312;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6311;
    OwnerPIN mPin;
    OwnerPIN mPuk;
    byte[] mData1;
    byte[] mData2;
    byte[] mData3;

    RSAPrivateKey mPrivateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, NO_EXTERNAL_ACCESS);
    RSAPublicKey mPublickKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, NO_EXTERNAL_ACCESS);
    KeyPair mKeyPair = new KeyPair(mPrivateKey, mPublickKey);

    /**
     * Installs this applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Java_card_applet();
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected Java_card_applet() {
        mKeyPair.genKeyPair();
        mPin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        mPuk = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
        byte[] pinArr = {0, 0, 0, 0};
        mPin.update(pinArr, (short) 0, (byte) pinArr.length);
        mPuk.update(pinArr, (short) 0, (byte) pinArr.length);
        register();
    }

    /**
     * Processes an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     */
    public void process(APDU apdu) {
        //Insert your code here
        byte[] buffer = apdu.getBuffer();
        if ((buffer[ISO7816.OFFSET_CLA] == 0)
                && (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4))) {
            return;
        }

        if (buffer[ISO7816.OFFSET_CLA] != APPLET_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case SET_DATA_1:
                storeData(apdu, (short) 1);
                return;
            case SET_DATA_2:
                storeData(apdu, (short) 2);
                return;
            case SET_DATA_3:
                storeData(apdu, (short) 3);
                return;
            case UNBLOCK:
                mPin.resetAndUnblock();
                return;
            case VERIFY:
                verify(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    }

    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (mPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    }

    private void storeData(APDU apdu, short type) {

        // access authentication
        if (!mPin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();
        short LC = apdu.getIncomingLength();
        byte[] store_data = new byte[(short) LC];
        short recivedDataLength = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();

        Util.arrayCopy(buffer, dataOffset, store_data, (short) 0, LC);
        apdu.receiveBytes(dataOffset);
        Util.arrayCopy(buffer, dataOffset, store_data, (short) 0, LC);

        switch (type) {
            case (short) 1:
                mData1 = store_data;
                break;
            case (short) 2:
                mData2 = store_data;
                break;
            default:
                mData3 = store_data;
                break;
        }

    }
}
