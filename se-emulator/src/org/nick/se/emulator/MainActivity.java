package org.nick.se.emulator;

import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.List;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener,
        KeyChainAliasCallback {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final int INSTALL_KEY_CODE = 42;
    private static final String SE_KEY_NAME = "my_se_key";

    private static final String TECH_ISO_PCDA = "android.nfc.tech.IsoPcdA";

    private TextView statusText;
    private EditText pkcs12FilenameText;
    private Button installPkcs12Button;
    private EditText pinText;
    private Button setPinButton;
    private TextView message;

    private NfcAdapter adapter;

    private PendingIntent pendingIntent;
    private IntentFilter[] filters;
    private String[][] techLists;

    private PkiApplet pkiApplet;
    private WakeLock wakeLock;

    private PowerManager powerManager;

    @SuppressLint("NewApi")
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        setContentView(R.layout.activity_main);

        setProgressBarIndeterminateVisibility(false);

        powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);

        statusText = (TextView) findViewById(R.id.status_text);
        pkcs12FilenameText = (EditText) findViewById(R.id.pkcs12FilenameText);
        installPkcs12Button = (Button) findViewById(R.id.install_pkcs12_button);
        installPkcs12Button.setOnClickListener(this);
        pinText = (EditText) findViewById(R.id.pin_text);
        setPinButton = (Button) findViewById(R.id.set_pin_button);
        setPinButton.setOnClickListener(this);
        message = (TextView) findViewById(R.id.message);

        adapter = NfcAdapter.getDefaultAdapter(this);
        adapter.setNdefPushMessage(null, this);
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN) {
            adapter.setBeamPushUris(null, this);
        }

        pendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
                getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        filters = new IntentFilter[] { new IntentFilter(
                NfcAdapter.ACTION_TECH_DISCOVERED) };
        techLists = new String[][] { { "android.nfc.tech.IsoPcdA" } };

        pkiApplet = new PkiApplet(this);
        statusText
                .setText(pkiApplet.isInitialized() ? R.string.applet_initialized
                        : R.string.applet_not_initialized);

        Intent intent = getIntent();
        String action = intent.getAction();
        Log.d(TAG, "Intent: " + intent);
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
            handleTag(intent);
        } else {
            message.setText(R.string.place_on_reader);
        }

    }

    @Override
    public void onResume() {
        Log.d(TAG, "onResume()");
        super.onResume();

        Log.d(TAG, "Acquiring wakelock");
        wakeLock = powerManager.newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK,
                getString(R.string.app_name));
        wakeLock.acquire();

        if (adapter != null) {
            adapter.enableForegroundDispatch(this, pendingIntent, filters,
                    techLists);
        }
    }

    @Override
    public void onPause() {
        Log.d(TAG, "onPause()");
        super.onPause();
        if (adapter != null) {
            Log.d(TAG, "disabling foreground dispatch");
            adapter.disableForegroundDispatch(this);
        }

        // we don't try to stop the applet thread here, because it is blocked
        // on I/O and there is really no way to interrupt it

        if (wakeLock != null) {
            wakeLock.release();
        }
    }

    @Override
    public void onDestroy() {
        Log.d(TAG, "onDestroy()");
        super.onDestroy();
        if (pkiApplet != null) {
            pkiApplet.stop();
        }
    }

    @Override
    public void onNewIntent(Intent intent) {
        Log.d(TAG, "onNewIntent()");
        handleTag(intent);

    }

    private void handleTag(Intent intent) {
        Log.d(TAG, "TECH_DISCOVERED: " + intent);
        message.setText("Discovered tag  with intent: " + intent);
        try {
            Tag tag = null;
            if (intent.getExtras() != null) {
                tag = (Tag) intent.getExtras().get(NfcAdapter.EXTRA_TAG);
            }
            if (tag == null) {
                return;
            }

            message.append("\n\n Tag: " + tag);
            List<String> techList = Arrays.asList(tag.getTechList());
            message.append("\n\n Tech list: " + techList);
            if (!techList.contains(TECH_ISO_PCDA)) {
                Log.e(TAG, "IsoPcdA not found in tech list");
                return;
            }

            TagWrapper tw = new TagWrapper(tag, TECH_ISO_PCDA);
            Log.d(TAG, "isConnected() " + tw.isConnected());
            if (!tw.isConnected()) {
                tw.connect();
            }

            message.append("\n");
            if (tag.getId() != null) {
                message.append("Tag ID: " + Crypto.toHex(tag.getId()));
                message.append("\n");
            }

            message.append("Max length: " + tw.getMaxTransceiveLength());
            message.append("\n");
            message.append("Staring PKI applet thread...");

            // stop and start a fresh thread for each new connection
            // shouldn't be needed since onNewIntent() is called only
            // after we enter the reader field again, and exiting it
            // should kill the previous thread
            if (pkiApplet != null) {
                Log.d(TAG, "Applet running: " + pkiApplet.isRunning());
                if (pkiApplet.isRunning()) {
                    Log.d(TAG, "Applet thread alredy running, stopping");
                    pkiApplet.stop();
                }
            }
            pkiApplet.start(tw);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onClick(View v) {
        try {
            switch (v.getId()) {
            case R.id.install_pkcs12_button:
                String pkcs12Filename = pkcs12FilenameText.getText().toString()
                        .trim();
                Intent intent = KeyChain.createInstallIntent();
                byte[] p12 = readFile(pkcs12Filename);
                intent.putExtra(KeyChain.EXTRA_PKCS12, p12);
                intent.putExtra(KeyChain.EXTRA_NAME, SE_KEY_NAME);
                startActivityForResult(intent, INSTALL_KEY_CODE);
                break;
            case R.id.set_pin_button:
                String pin = pinText.getText().toString().trim();
                if (pin != null && pin.length() != 0) {
                    pkiApplet.setPin(pin);
                    pinText.setText(null);
                    Toast.makeText(this, "Set PIN to : " + pin,
                            Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "Enter a non-empty PIN",
                            Toast.LENGTH_SHORT).show();
                }
                break;
            default:
                //
            }
        } catch (Exception e) {
            Log.e(TAG, "Error: " + e.getMessage(), e);
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == INSTALL_KEY_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                chooseKey();
            } else {
                super.onActivityResult(requestCode, resultCode, data);
            }
        }
    }

    private void chooseKey() {
        KeyChain.choosePrivateKeyAlias(this, this, new String[] { "RSA" },
                null, null, -1, SE_KEY_NAME);
    }

    private static byte[] readFile(String filename) throws Exception {
        File f = new File(Environment.getExternalStorageDirectory(), filename);
        byte[] result = new byte[(int) f.length()];
        FileInputStream in = new FileInputStream(f);
        in.read(result);
        in.close();

        return result;
    }

    @Override
    public void alias(final String alias) {
        Log.d(TAG, "selected alias: " + alias);
        pkiApplet.setAlias(alias);
    }

}
