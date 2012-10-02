package org.nick.se.emulator;

import static org.nick.se.emulator.ISO7816.CLA_ISO7816;
import static org.nick.se.emulator.ISO7816.FILE_NOT_FOUND;
import static org.nick.se.emulator.ISO7816.INS_SELECT;
import static org.nick.se.emulator.ISO7816.OFFSET_CDATA;
import static org.nick.se.emulator.ISO7816.OFFSET_CLA;
import static org.nick.se.emulator.ISO7816.OFFSET_INS;
import static org.nick.se.emulator.ISO7816.OFFSET_LC;
import static org.nick.se.emulator.ISO7816.SW_CLA_NOT_SUPPORTED;
import static org.nick.se.emulator.ISO7816.SW_CONDITIONS_NOT_SATISFIED;
import static org.nick.se.emulator.ISO7816.SW_INS_NOT_SUPPORTED;
import static org.nick.se.emulator.ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED;
import static org.nick.se.emulator.ISO7816.SW_SUCCESS;
import static org.nick.se.emulator.ISO7816.SW_UNKNOWN;
import static org.nick.se.emulator.ISO7816.SW_WRONG_LENGTH;

import java.io.IOException;
import java.security.PrivateKey;
import java.util.Arrays;

import android.content.Context;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.util.Log;

public class PkiApplet {

    private static final String TAG = PkiApplet.class.getSimpleName();

    private static final String PIN_KEY = "pin";
    private static final String KEY_ALIAS_KEY = "key_alias";

    private static final byte[] SELECT_PKI_APPLET_CMD = { 0x00, (byte) 0xA4,
            0x04, 0x00, 0x06, (byte) 0xA0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01 };

    // applet commands
    private final static byte PKI_APPLET_CLA = (byte) 0x80;
    private final static byte INS_VERIFY_PIN = (byte) 0x01;
    private final static byte INS_SIGN_DATA = (byte) 0x02;

    private Context ctx;
    private TagWrapper tag;

    private boolean selected = false;
    private boolean authenticated = false;

    private volatile boolean isRunning = false;

    private Thread appletThread;

    public PkiApplet(Context ctx) {
        this.ctx = ctx;
    }

    public void start(TagWrapper tag) throws IOException {
        this.tag = tag;

        Runnable r = new Runnable() {
            public void run() {
                try {
                    // send dummy data to get first command APDU
                    // at least two bytes to keep smartcardio happy
                    byte[] cmd = transceive(new byte[] { (byte) 0x90, 0x00 });
                    do {
                        if (!selected) {
                            if (Arrays.equals(cmd, SELECT_PKI_APPLET_CMD)) {
                                selected = true;
                                Log.d(TAG, "SELECT success");
                                cmd = transceive(toBytes(SW_SUCCESS));
                            } else {
                                if (cmd[OFFSET_CLA] == CLA_ISO7816
                                        && cmd[OFFSET_INS] == INS_SELECT) {
                                    Log.e(TAG,
                                            "Invalid AID: " + Crypto.toHex(cmd));
                                    cmd = transceive(toBytes(FILE_NOT_FOUND));
                                } else {
                                    Log.e(TAG,
                                            "First command must be a SELECT: "
                                                    + Crypto.toHex(cmd));
                                    cmd = transceive(toBytes(SW_UNKNOWN));
                                }
                                break;
                            }
                        } else {
                            if (Arrays.equals(cmd, SELECT_PKI_APPLET_CMD)) {
                                cmd = transceive(toBytes(SW_SUCCESS));
                            }
                        }

                        if (!isInitialized()) {
                            Log.e(TAG, "Applet not initialized");
                            cmd = transceive(toBytes(SW_CONDITIONS_NOT_SATISFIED));
                            break;
                        }

                        if (cmd[OFFSET_CLA] != PKI_APPLET_CLA) {
                            Log.e(TAG,
                                    "Unsupported command class: "
                                            + Crypto.toHex(cmd));
                            cmd = transceive(toBytes(SW_CLA_NOT_SUPPORTED));
                            break;
                        }

                        if (cmd[OFFSET_INS] != INS_VERIFY_PIN
                                && cmd[OFFSET_INS] != INS_SIGN_DATA) {
                            Log.e(TAG,
                                    "Unsupported instruction: "
                                            + Crypto.toHex(cmd));
                            cmd = transceive(toBytes(SW_INS_NOT_SUPPORTED));
                            break;
                        }

                        byte ins = cmd[OFFSET_INS];
                        switch (ins) {
                        case INS_VERIFY_PIN:
                            if (cmd.length < 5) {
                                Log.e(TAG, "Expecting command with data: "
                                        + Crypto.toHex(cmd));
                                cmd = transceive(toBytes(SW_WRONG_LENGTH));
                                break;
                            }

                            int dataLen = cmd[OFFSET_LC];
                            byte[] pinData = Arrays.copyOfRange(cmd,
                                    OFFSET_CDATA, OFFSET_CDATA + dataLen);
                            String pin = new String(pinData, "ASCII");
                            if (Crypto.checkPassword(getPin(), pin)) {
                                Log.d(TAG, "VERIFY PIN success");
                                cmd = transceive(toBytes(SW_SUCCESS));
                                authenticated = true;
                            } else {
                                Log.w(TAG, "Invalid PIN");
                                cmd = transceive(toBytes(SW_SECURITY_STATUS_NOT_SATISFIED));
                            }
                            break;
                        case INS_SIGN_DATA:
                            if (cmd.length < 5) {
                                Log.e(TAG, "Expecting command with data: "
                                        + Crypto.toHex(cmd));
                                cmd = transceive(toBytes(SW_WRONG_LENGTH));
                                break;
                            }
                            if (!authenticated) {
                                Log.w(TAG, "Need to authenticate first");
                                cmd = transceive(toBytes(SW_SECURITY_STATUS_NOT_SATISFIED));
                                break;
                            }

                            dataLen = cmd[OFFSET_LC];
                            byte[] signedData = Arrays.copyOfRange(cmd,
                                    OFFSET_CDATA, OFFSET_CDATA + dataLen);
                            try {
                                PrivateKey pk = KeyChain.getPrivateKey(ctx,
                                        getAlias());
                                byte[] signature = Crypto.sign(pk, signedData);

                                byte[] response = new byte[signature.length + 2];
                                System.arraycopy(signature, 0, response, 0,
                                        signature.length);
                                System.arraycopy(toBytes(SW_SUCCESS), 0,
                                        response, signature.length, 2);
                                Log.d(TAG, "SIGN DATA success");
                                cmd = transceive(response);
                            } catch (Exception e) {
                                Log.d(TAG, "Error: " + e.getMessage(), e);
                                cmd = transceive(toBytes(SW_UNKNOWN));
                            }
                            break;
                        }
                    } while (cmd != null && !Thread.interrupted());
                } catch (Exception e) {
                    Log.e(TAG, "SE error: " + e.getMessage(), e);
                    Log.d(TAG, String.format("Stopping applet thread '%s'",
                            appletThread.getName()));
                    resetState();
                    // a bit more explicit
                    isRunning = false;
                    return;
                }
                // if interrupted
                isRunning = false;
            }
        };

        appletThread = new Thread(r);
        appletThread.setName("PKI applet thread#" + appletThread.getId());
        appletThread.start();
        isRunning = true;
        Log.d(TAG,
                String.format("Started applet thread '%s'",
                        appletThread.getName()));
    }

    public boolean isRunning() {
        return isRunning;
    }

    public synchronized void stop() {
        Log.d(TAG, "stopping applet thread");
        if (appletThread != null) {
            appletThread.interrupt();
            Log.d(TAG, "applet thread running: " + isRunning);
        }

        Log.d(TAG, "Resetting applet state");
        resetState();
    }

    private byte[] transceive(byte[] cmd) throws IOException {
        Log.d(TAG,
                String.format("[%s] --> %s", appletThread.getName(),
                        Crypto.toHex(cmd)));
        byte[] response = tag.transceive(cmd);
        Log.d(TAG,
                String.format("[%s] <-- %s", appletThread.getName(),
                        Crypto.toHex(response)));

        return response;
    }

    public String getAlias() {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(
                KEY_ALIAS_KEY, null);
    }

    public void setAlias(String alias) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putString(KEY_ALIAS_KEY, alias).commit();
    }

    public String getPin() {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(
                PIN_KEY, null);
    }

    public void setPin(String pin) {
        String protectedPin = Crypto.protectPassword(pin);
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putString(PIN_KEY, protectedPin).commit();
    }

    private static byte[] toBytes(short s) {
        return new byte[] { (byte) ((s & 0xff00) >> 8), (byte) (s & 0xff) };
    }

    public boolean isInitialized() {
        return getAlias() != null && getPin() != null;
    }

    private void resetState() {
        selected = false;
        authenticated = false;
        if (tag != null) {
            try {
                if (tag.isConnected()) {
                    tag.close();
                }
                tag = null;
            } catch (IOException e) {
                Log.w(TAG, "Error closing tag: " + e.getMessage(), e);
            }
        }
    }
}
