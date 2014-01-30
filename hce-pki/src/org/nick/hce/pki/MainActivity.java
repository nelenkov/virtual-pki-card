package org.nick.hce.pki;

import java.io.File;
import java.io.FileInputStream;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
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

    private TextView statusText;
    private EditText pkcs12FilenameText;
    private Button installPkcs12Button;
    private EditText pinText;
    private Button setPinButton;
    private TextView message;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        setContentView(R.layout.activity_main);

        setProgressBarIndeterminateVisibility(false);

        statusText = (TextView) findViewById(R.id.status_text);
        pkcs12FilenameText = (EditText) findViewById(R.id.pkcs12FilenameText);
        installPkcs12Button = (Button) findViewById(R.id.install_pkcs12_button);
        installPkcs12Button.setOnClickListener(this);
        pinText = (EditText) findViewById(R.id.pin_text);
        setPinButton = (Button) findViewById(R.id.set_pin_button);
        setPinButton.setOnClickListener(this);
        message = (TextView) findViewById(R.id.message);

        message.setText(R.string.place_on_reader);
        statusText
                .setText(PkiHostApduService.isInitialized(this) ? R.string.applet_initialized
                        : R.string.applet_not_initialized);
    }

    @Override
    public void onResume() {
        super.onResume();
        statusText
                .setText(PkiHostApduService.isInitialized(this) ? R.string.applet_initialized
                        : R.string.applet_not_initialized);
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
                    PkiHostApduService.setPin(pin, this);
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
        PkiHostApduService.setAlias(alias, this);
    }

}
