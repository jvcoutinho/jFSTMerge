package br.ufpe.cin.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.ArrayUtils;

import br.ufpe.cin.exceptions.CryptoException;

public final class FileEncrypterDecrypter {

    private final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private final int KEY_SIZE = 256;
    private final char[] KEY_STORE_PASSWORD = "thisiss3mkeystorepassword".toCharArray();
    private final SecureRandom secureRandom = new SecureRandom();
    private final Path keyStorePath = Paths.get(System.getProperty("user.home"), "keystore.ks");

    public void cipher(File plainFile, File cipherFile) throws CryptoException {
        try {
            SecretKey key = generateKey();
            storeKey(key, cipherFile.getName());

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            IvParameterSpec iv = generateIV(cipher);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] plainText = FileUtils.readFileToByteArray(plainFile);
            byte[] cipherText = cipher.doFinal(plainText);
            FileUtils.writeByteArrayToFile(cipherFile, ArrayUtils.addAll(iv.getIV(), cipherText));

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException
                | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Error encrypting file " + plainFile.getAbsolutePath(), e);
        }
    }

    public void decipher(File cipherFile, File plainFile) throws CryptoException {
        try {
            SecretKey key = loadKey(cipherFile, cipherFile.getName());

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            byte[] cipherTextAndIV = FileUtils.readFileToByteArray(cipherFile);
            byte[] iv = ArrayUtils.subarray(cipherTextAndIV, 0, cipher.getBlockSize());

            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            
            byte[] cipherText = ArrayUtils.subarray(cipherTextAndIV, iv.length, cipherTextAndIV.length);
            byte[] plainText = cipher.doFinal(cipherText);
            FileUtils.writeByteArrayToFile(plainFile, plainText);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException
                | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Error decrypting file " + cipherFile.getAbsolutePath(), e);
        }
    }

    private IvParameterSpec generateIV(Cipher cipher) {
        byte[] iv = new byte[cipher.getBlockSize()];
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private SecretKey loadKey(File cipherFile, String entryName) throws CryptoException {
        try (InputStream keyStoreData = new FileInputStream(keyStorePath.toString())) {

            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(keyStoreData, KEY_STORE_PASSWORD);

            return (SecretKey) keyStore.getKey(entryName, KEY_STORE_PASSWORD);

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableEntryException e) {
            throw new CryptoException("Error loading symmetric key", e);
        }
    }

    private void storeKey(SecretKey key, String entryName) throws CryptoException {
        
        try {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");

            if(!Files.exists(keyStorePath)) {
                keyStore.load(null, KEY_STORE_PASSWORD);
            } else {
                InputStream keyStoreData = new FileInputStream(keyStorePath.toString());
                keyStore.load(keyStoreData, KEY_STORE_PASSWORD);
                keyStoreData.close();
            }            
            
            SecretKeyEntry secretKeyEntry = new SecretKeyEntry(key);
            ProtectionParameter entryPassword = new PasswordProtection(KEY_STORE_PASSWORD);
            keyStore.setEntry(entryName, secretKeyEntry, entryPassword);

            OutputStream keyStoreOutputStream = new FileOutputStream(keyStorePath.toString());
            keyStore.store(keyStoreOutputStream, KEY_STORE_PASSWORD);
        
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new CryptoException("Error storing symmetric key", e);
        }
    }

    private SecretKey generateKey() throws CryptoException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE, secureRandom);

            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Error generating symmetric key", e);
        }
        
    }


}

