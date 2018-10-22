package com.uam.wmi.fmt.keepassbsm;

import android.support.annotation.NonNull;
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
import javax.crypto.spec.


public class Cipherix {
    public static final int SALT_BYTE_SIZE = 24;

    byte[] salt;
    String firstHash;

    // hexArr for getHash
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


    Cipherix(String plaintext) throws UnsupportedEncodingException, NoSuchAlgorithmException {
//        encrypt(plaintext.getBytes("UTF-8"));
        //Generate 64 byte salt
        SecureRandom random = new SecureRandom();
        salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);

        firstHash = getHash(plaintext, salt);
    }

    public boolean checkHashes(String plaintext) throws NoSuchAlgorithmException {
        return getHash(plaintext, salt).equals(firstHash);
    }


    private static String getHash(String plaintext, byte[] salt) throws NoSuchAlgorithmException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(plaintext.getBytes());

        byte[] messageDigest = digest.digest();

        char[] hexChars = new char[messageDigest.length * 2];
        for ( int j = 0; j < messageDigest.length; j++ ) {
            int v = messageDigest[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars);
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
