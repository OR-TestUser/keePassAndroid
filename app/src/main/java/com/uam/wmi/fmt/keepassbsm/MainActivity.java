package com.uam.wmi.fmt.keepassbsm;

import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class MainActivity extends Cipherator {

    String tag = getClass().getName();

    private TextView textView;

    private String cipherMSG = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        textView = findViewById(R.id.MSGeditText);
        cipherMSG = SPutils.getString(this, "encryptedMSG");
        if (cipherMSG == "") {
            textView.setText("");
        } else {
            decryptMsg(cipherMSG);
        }

        findViewById(R.id.password_new_applyButton).setOnClickListener(view -> {
            try {
                passwordChange(view);
            } catch (Throwable e) {
                e.printStackTrace();
            }
        });

        findViewById(R.id.saveButton).setOnClickListener(view -> encryptMsg(view));

        findViewById(R.id.fab).setOnClickListener(view -> {
            Toast.makeText(this, "Logged out", Toast.LENGTH_SHORT).show();
            finish();
        });
    }

    private void passwordChange(View view) throws IOException, BadPaddingException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, CertificateException {

        EditText cp = findViewById(R.id.text_current_password);
        EditText np = findViewById(R.id.text_password_new);
        EditText rnp = findViewById(R.id.text_password_new_repeated);

        String newPassword = np.getText().toString();
        String repeatedNewPassword = rnp.getText().toString();
        String currentPassword = cp.getText().toString();

        if (newPassword.equals(repeatedNewPassword)){
            Passport passportCheck = new Passport(this, currentPassword);
            if (passportCheck.didPass()) {
                SPutils.purgeUserLocalStorage(this);
                Passport passport = new Passport(this, newPassword);
                encryptMsg(view); // encrypting with new sekerets
                Toast.makeText(this, "Password changed!", Toast.LENGTH_SHORT).show();
                finish();
            } else {
                Toast.makeText(this, "Wrong current password!", Toast.LENGTH_SHORT).show();
                cp.setText("");
            }
        } else {
            Toast.makeText(this, "Fill new password again!", Toast.LENGTH_SHORT).show();
            np.setText("");
            rnp.setText("");
        }

    }

    private void encryptMsg(View view) {
        Toast.makeText(this, "encryptMsg", Toast.LENGTH_SHORT).show();

        String toEncryptString = textView.getText().toString();
        try {
            final HashMap<String, byte[]> map = encrypt(toEncryptString.getBytes("UTF-8"));
            SPutils.putKeyValue(this, "encryptedMSG", toBase64(map.get("encrypted")));
            SPutils.putKeyValue(this, "ivMSG", toBase64(map.get("iv")));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    private void decryptMsg(String cipher) {
        Toast.makeText(this, "decryptMsg", Toast.LENGTH_SHORT).show();

        HashMap<String, byte[]> map = new HashMap<>();
        map.put("iv", fromBase64(SPutils.getString(this, "ivMSG")));
        map.put("encrypted", fromBase64(cipher));
        try {
            final byte[] decryptedBytes = decrypt(map);
            final String decryptedString = new String(decryptedBytes, "UTF-8");
            textView.setText(decryptedString);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }




}
