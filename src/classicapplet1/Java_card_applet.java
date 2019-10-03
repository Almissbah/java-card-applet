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

        byte[] pinArr = {0, 0, 0, 0};
        mPin.update(pinArr, (short) 0, (byte) pinArr.length);
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
    }
}
