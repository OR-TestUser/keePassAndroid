package com.uam.wmi.fmt.keepassbsm;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public abstract class Cipherator extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

    }

    // KeyStore
    private SecretKey getTheKey()
            throws KeyStoreException,NoSuchAlgorithmException,IOException,
            CertificateException, UnrecoverableEntryException {

        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("MyKeyAlias", null);
        final SecretKey secretKey = secretKeyEntry.getSecretKey();

        return secretKey;
    }

    protected HashMap<String, byte[]> encrypt(final byte[] decryptBytes)
            throws NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException,
            KeyStoreException, CertificateException, IOException,
            UnrecoverableEntryException, InvalidKeyException {

        final HashMap<String, byte[]> map = new HashMap<>();

        //Encrypt data
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getTheKey());
        final byte[] ivBytes = cipher.getIV();
        final byte[] encryptedBytes = cipher.doFinal(decryptBytes);
        map.put("iv", ivBytes);
        map.put("encrypted", encryptedBytes);

        return map;
    }

    protected byte[] decrypt(final HashMap<String, byte[]> map)
            throws NoSuchPaddingException, NoSuchAlgorithmException,
            IOException, CertificateException, UnrecoverableEntryException,
            KeyStoreException, IllegalBlockSizeException, InvalidKeyException,
            InvalidAlgorithmParameterException, BadPaddingException {

        byte[] decryptedBytes = null;

        final byte[] encryptedBytes = map.get("encrypted");
        final byte[] ivBytes = map.get("iv");

        //Decrypt data
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec spec = new GCMParameterSpec(128, ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, getTheKey(), spec);
        decryptedBytes = cipher.doFinal(encryptedBytes);

        return decryptedBytes;
    }

    protected static byte[] fromBase64(String hex) {

        return Base64.decode(hex, Base64.DEFAULT);
    }

    protected static String toBase64(byte[] array) {

        return Base64.encodeToString(array, Base64.DEFAULT);
    }
}
