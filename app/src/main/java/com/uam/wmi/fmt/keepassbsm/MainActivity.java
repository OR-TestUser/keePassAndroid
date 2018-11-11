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
import android.widget.TextView;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;


public class MainActivity extends Cipherator {

    String tag = getClass().getName();

    TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        textView = findViewById(R.id.MSGeditText);
        String cipherMSG = SPutils.getString(this, "encryptedMSG");
        if (cipherMSG == "") {
            textView.setText("");
        } else {
            decryptMsg(cipherMSG);
        }


        findViewById(R.id.saveButton).setOnClickListener(view -> encryptMsg(view));

        findViewById(R.id.fab).setOnClickListener(view -> {
            Toast.makeText(this, "Logged out", Toast.LENGTH_SHORT).show();
            finish();
        });
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
