package com.uam.wmi.fmt.keepassbsm;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.acl.LastOwnerException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;


// https://developer.android.com/training/articles/keystore#java


public class Passport {

    String tag = getClass().getName();

    public static final int SALT_BYTE_SIZE = 24;
    public static final int HASH_BYTE_SIZE = 18;
    public static final int PBKDF2_ITERATIONS = 64000;

    boolean pass;

    Passport(Context context, String plaintext)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, KeyStoreException, IOException,
            BadPaddingException, CertificateException, InvalidKeyException, UnrecoverableEntryException {

//        firstHash = createHash(plaintext);
//        Log.d("firstHash", firstHash);
//        Log.d("shouldBe", " " + verifyPassword("test".toCharArray(), firstHash));
//        testEncryption();

        if (SPutils.keyStoreSaved(context)){
            // load keystore
            Log.e(tag, "load keystore");

            HashMap<String, byte[]> map = new HashMap<>();
            map.put("iv", fromBase64(SPutils.getString(context, "iv")));
            map.put("encrypted", fromBase64(SPutils.getString(context, "encrypted")));

            final byte[] decryptedBytes = decrypt(map);
            final String decryptedString = new String(decryptedBytes, "UTF-8");
            Log.e(tag, "The decrypted string is " + decryptedString);
//            Log.e(tag, " " + verifyPassword("test".toCharArray(), decryptedString));

            pass = verifyPassword(plaintext.toCharArray(), decryptedString);
        } else {
            //Create store with new password etc...
            Log.e(tag, "create keystore");
            createKeyStore(context);

            String hash = createHash(plaintext);
            final HashMap<String, byte[]> map =  encrypt(hash.getBytes("UTF-8"));

            SPutils.putKeyValue(context, "encrypted", toBase64(map.get("encrypted")));
            SPutils.putKeyValue(context, "iv", toBase64(map.get("iv")));
            pass = true;
        }
    }

    public boolean didPass() {
        return pass;
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

    private HashMap<String, byte[]> encrypt(final byte[] decryptBytes)
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

    private byte[] decrypt(final HashMap<String, byte[]> map)
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

    private void createKeyStore(Context context) throws
        NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        //Generate a key and store it in the KeyStore
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder("MyKeyAlias",
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                //.setUserAuthenticationRequired(true) //requires lock screen, invalidated if lock screen is disabled
                //.setUserAuthenticationValidityDurationSeconds(120) //only available x seconds from password authentication. -1 requires finger print - every time
                .setRandomizedEncryptionRequired(true) //different ciphertext for same plaintext on each call
                .build();
        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();

        SPutils.keyStoreInit(context);
    }


    @TargetApi(Build.VERSION_CODES.M)
    private void testEncryption(Context context)
    {
        try
        {
            createKeyStore(context);

            //Test
            final HashMap<String, byte[]> map = encrypt("My very sensitive string!".getBytes("UTF-8"));

            Log.e(tag, map.toString());
            final byte[] decryptedBytes = decrypt(map);
            final String decryptedString = new String(decryptedBytes, "UTF-8");
            Log.e(tag, "The decrypted string is " + decryptedString);
        }
        catch (Throwable e)
        {
            e.printStackTrace();
        }
    }
}
