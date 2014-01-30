package org.nick.hce.pki;

import static org.nick.hce.pki.ISO7816.CLA_ISO7816;
import static org.nick.hce.pki.ISO7816.FILE_NOT_FOUND;
import static org.nick.hce.pki.ISO7816.INS_SELECT;
import static org.nick.hce.pki.ISO7816.OFFSET_CDATA;
import static org.nick.hce.pki.ISO7816.OFFSET_CLA;
import static org.nick.hce.pki.ISO7816.OFFSET_INS;
import static org.nick.hce.pki.ISO7816.OFFSET_LC;
import static org.nick.hce.pki.ISO7816.SW_CLA_NOT_SUPPORTED;
import static org.nick.hce.pki.ISO7816.SW_CONDITIONS_NOT_SATISFIED;
import static org.nick.hce.pki.ISO7816.SW_INS_NOT_SUPPORTED;
import static org.nick.hce.pki.ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
import static org.nick.hce.pki.ISO7816.SW_SUCCESS;
import static org.nick.hce.pki.ISO7816.SW_UNKNOWN;
import static org.nick.hce.pki.ISO7816.SW_WRONG_LENGTH;

import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.util.Arrays;

import android.content.Context;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.util.Log;

public class PkiHostApduService extends HostApduService {

    private static final String TAG = PkiHostApduService.class.getSimpleName();

    private static final String PIN_KEY = "pin";
    private static final String KEY_ALIAS_KEY = "key_alias";

    private static final byte[] SELECT_PKI_APPLET_CMD = { 0x00, (byte) 0xA4,
            0x04, 0x00, 0x06, (byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01 };

    // applet commands
    private final static byte PKI_APPLET_CLA = (byte) 0x80;
    private final static byte INS_VERIFY_PIN = (byte) 0x01;
    private final static byte INS_SIGN_DATA = (byte) 0x02;

    private boolean selected = false;
    private boolean authenticated = false;

    @Override
    public void onDeactivated(int reason) {
        Log.d(TAG, "deactivated. reason=" + reason);
        selected = false;
        authenticated = false;
    }

    @Override
    public byte[] processCommandApdu(byte[] cmd, Bundle extras) {
        Log.d(TAG, "APDU: " + Crypto.toHex(cmd));

        if (!selected) {
            if (Arrays.equals(cmd, SELECT_PKI_APPLET_CMD)) {
                selected = true;
                Log.d(TAG, "SELECT success");

                return toBytes(SW_SUCCESS);
            }

            if (cmd[OFFSET_CLA] == CLA_ISO7816 && cmd[OFFSET_INS] == INS_SELECT) {
                Log.e(TAG, "Invalid AID: " + Crypto.toHex(cmd));

                return toBytes(FILE_NOT_FOUND);
            }

            Log.e(TAG, "First command must be a SELECT: " + Crypto.toHex(cmd));
            return toBytes(SW_UNKNOWN);
        }

        if (Arrays.equals(cmd, SELECT_PKI_APPLET_CMD)) {
            return toBytes(SW_SUCCESS);
        }

        if (!isInitialized()) {
            Log.e(TAG, "Applet not initialized");

            return toBytes(SW_CONDITIONS_NOT_SATISFIED);
        }

        if (cmd[OFFSET_CLA] != PKI_APPLET_CLA) {
            Log.e(TAG, "Unsupported command class: " + Crypto.toHex(cmd));
            return toBytes(SW_CLA_NOT_SUPPORTED);
        }

        if (cmd[OFFSET_INS] != INS_VERIFY_PIN
                && cmd[OFFSET_INS] != INS_SIGN_DATA) {
            Log.e(TAG, "Unsupported instruction: " + Crypto.toHex(cmd));
            return toBytes(SW_INS_NOT_SUPPORTED);
        }

        byte ins = cmd[OFFSET_INS];
        switch (ins) {
        case INS_VERIFY_PIN:
            if (cmd.length < 5) {
                Log.e(TAG, "Expecting command with data: " + Crypto.toHex(cmd));
                return toBytes(SW_WRONG_LENGTH);
            }

            int dataLen = cmd[OFFSET_LC];
            byte[] pinData = Arrays.copyOfRange(cmd, OFFSET_CDATA, OFFSET_CDATA
                    + dataLen);
            String pin = asciiBytesToStr(pinData);
            if (Crypto.checkPassword(getPin(), pin)) {
                Log.d(TAG, "VERIFY PIN success");
                authenticated = true;

                return toBytes(SW_SUCCESS);
            }

            Log.w(TAG, "Invalid PIN");
            return toBytes(SW_SECURITY_STATUS_NOT_SATISFIED);
        case INS_SIGN_DATA:
            if (cmd.length < 5) {
                Log.e(TAG, "Expecting command with data: " + Crypto.toHex(cmd));
                return toBytes(SW_WRONG_LENGTH);
            }

            if (!authenticated) {
                Log.w(TAG, "Need to authenticate first");
                return toBytes(SW_SECURITY_STATUS_NOT_SATISFIED);
            }

            dataLen = cmd[OFFSET_LC];
            final byte[] signedData = Arrays.copyOfRange(cmd, OFFSET_CDATA,
                    OFFSET_CDATA + dataLen);

            Runnable r = new Runnable() {
                @Override
                public void run() {
                    try {
                        PrivateKey pk = KeyChain.getPrivateKey(
                                PkiHostApduService.this, getAlias());
                        byte[] signature = Crypto.sign(pk, signedData);

                        byte[] response = new byte[signature.length + 2];
                        System.arraycopy(signature, 0, response, 0,
                                signature.length);
                        System.arraycopy(toBytes(SW_SUCCESS), 0, response,
                                signature.length, 2);
                        Log.d(TAG, "SIGN DATA success");
                        Log.d(TAG, "response: " + Crypto.toHex(response));
                        sendResponseApdu(response);
                    } catch (Exception e) {
                        Log.d(TAG, "Error: " + e.getMessage(), e);
                        sendResponseApdu(toBytes(SW_UNKNOWN));
                    }
                }

            };
            Thread t = new Thread(r);
            t.start();

            return null;
        }

        return toBytes(ISO7816.SW_UNKNOWN);
    }

    private String asciiBytesToStr(byte[] pinData) {
        try {
            return new String(pinData, "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] toBytes(short s) {
        return new byte[] { (byte) ((s & 0xff00) >> 8), (byte) (s & 0xff) };
    }

    public String getAlias() {
        return getAlias(this);
    }

    public static String getAlias(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(
                KEY_ALIAS_KEY, null);
    }

    public static void setAlias(String alias, Context ctx) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putString(KEY_ALIAS_KEY, alias).commit();
    }

    public String getPin() {
        return getPin(this);
    }

    public static String getPin(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(
                PIN_KEY, null);
    }

    public static void setPin(String pin, Context ctx) {
        String protectedPin = Crypto.protectPassword(pin);
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putString(PIN_KEY, protectedPin).commit();
    }

    public boolean isInitialized() {
        return getAlias() != null && getPin() != null;
    }

    public static boolean isInitialized(Context ctx) {
        return getAlias(ctx) != null && getPin(ctx) != null;
    }

}
