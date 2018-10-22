package com.uam.wmi.fmt.keepassbsm;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

// https://developer.android.com/training/articles/keystore#javał


public class Passport {

    public static final int SALT_BYTE_SIZE = 24;
    public static final int HASH_BYTE_SIZE = 18;
    public static final int PBKDF2_ITERATIONS = 64000;

    String firstHash;

    Passport(String plaintext) throws InvalidKeySpecException, NoSuchAlgorithmException {
        firstHash = createHash(plaintext);
        Log.d("firstHash", firstHash);
        Log.d("shouldBe", " " + verifyPassword("test".toCharArray(), firstHash));
    }

    public static String createHash(String password) throws InvalidKeySpecException, NoSuchAlgorithmException { return createHash(password.toCharArray()); }
    public static String createHash(char[] password)
        throws InvalidKeySpecException, NoSuchAlgorithmException {

        // Creating a salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);

        //Hashing the password
        byte[] hash = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
        int hashSize = hash.length;


        // format: algo:iter:hashSize:salt:hash
        String parts = "sha256:" +
                PBKDF2_ITERATIONS + ":" +
                hashSize + ":" +
                toBase64(salt) + ":" +
                toBase64(hash);

        return parts;
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        return secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
    }

    public static boolean verifyPassword(char[] password, String correctHash)
        throws InvalidKeySpecException, NoSuchAlgorithmException {
        String[] params = correctHash.split(":");

        String algo = params[0];
        int iterations = Integer.parseInt(params[1]);
        int storedHashSize = Integer.parseInt(params[2]);
        byte[] salt = fromBase64(params[3]);
        byte[] hash = fromBase64(params[4]);


        byte[] testHash = pbkdf2(password, salt, iterations, storedHashSize);

        return toBase64(testHash).equals(toBase64(hash));
    }

    private static byte[] fromBase64(String hex) {

        return Base64.decode(hex, Base64.DEFAULT);
    }

    private static String toBase64(byte[] array) {

        return Base64.encodeToString(array, Base64.DEFAULT);
    }




    // KeyStore Try

    public static void Nothing()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder("MyKeyAlias",
                KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build();

        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();





    }

}
