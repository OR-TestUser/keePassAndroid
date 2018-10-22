package com.uam.wmi.fmt.keepassbsm;

import android.util.Log;
import android.util.Xml;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Cipherix {
    byte[] salt, firstHash;
    MessageDigest md;

    Cipherix(String plaintext) throws UnsupportedEncodingException, NoSuchAlgorithmException {
//        encrypt(plaintext.getBytes("UTF-8"));
        //Generate 64 byte salt
        SecureRandom random = new SecureRandom();
        salt = new byte[256];
        random.nextBytes(salt);
        md = MessageDigest.getInstance("SHA-256");

        firstHash = saltyHashPLZ(plaintext);
    }

    public boolean checkHashes(String plaintext) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        return saltyHashPLZ(plaintext).equals(firstHash);
    }

    private byte[] saltyHashPLZ(String plaintext) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        Log.d("flaga   salt", salt.toString());

        byte[] passwordBytes = plaintext.getBytes("UTF-8");

        md.reset();
        md.update(salt);
        byte[] hashBytes = md.digest(passwordBytes);
        Log.d("flaga return", String.valueOf(hashBytes));

        return hashBytes;
    }







//    private static void encrypt(byte[] plaintext) throws NoSuchAlgorithmException {
//        KeyGenerator keygen = KeyGenerator.getInstance("AES");
//        keygen.init(256);
//        SecretKey key = keygen.generateKey();
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
//        cipher.init(Cipher.ENCRYPT_MODE, key);
//        byte[] ciphertext = cipher.doFinal(plaintext);
//        byte[] iv = cipher.getIV();
//    }
}
