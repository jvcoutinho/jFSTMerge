package br.ufpe.cin.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.FileUtils;

import br.ufpe.cin.exceptions.CryptoException;

public final class CryptoUtils {

    private final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private final int KEY_SIZE = 256;
    private final char[] KEY_STORE_PASSWORD = "thisiss3mkeystorepassword".toCharArray();

    public void cipher(File plainFile, File cipherFile) throws CryptoException {
        try {
            SecretKey key = generateKey();
            storeKey(key, plainFile.getName());

            doCrypto(key, Cipher.ENCRYPT_MODE, plainFile, cipherFile);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Error encrypting file " + plainFile.getAbsolutePath(), e);
        }
    }

    public void decipher(File cipherFile, File plainFile) throws CryptoException {
        try {
            SecretKey key = loadKey(cipherFile, cipherFile.getName());

            doCrypto(key, Cipher.DECRYPT_MODE, cipherFile, plainFile);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IOException
                | IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoException("Error decrypting file " + cipherFile.getAbsolutePath(), e);
        }
    }

    
    private void doCrypto(SecretKey key, int encryptMode, File input, File output) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(encryptMode, key);

        byte[] plainText = FileUtils.readFileToByteArray(input);
        byte[] cipherText = cipher.doFinal(plainText);
        FileUtils.writeByteArrayToFile(output, cipherText);
    }

    private SecretKey loadKey(File cipherFile, String entryName) throws CryptoException {
        try (InputStream keyStoreData = new FileInputStream("keystore.ks")) {

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(keyStoreData, KEY_STORE_PASSWORD);

            ProtectionParameter entryPassword = new PasswordProtection(KEY_STORE_PASSWORD);
            return (SecretKey) ((PrivateKeyEntry) keyStore.getEntry(entryName, entryPassword)).getPrivateKey();

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableEntryException e) {
            throw new CryptoException("Error loading symmetric key", e);
        }
    }

    private void storeKey(SecretKey key, String entryName) throws CryptoException {
        
        try(InputStream keyStoreData = new FileInputStream("C:\\Users\\jvsfc\\Desktop\\jFSTMerge\\src\\main\\java\\br\\ufpe\\cin\\crypto\\keystore.ks")) {
            
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(keyStoreData, KEY_STORE_PASSWORD);
            
            SecretKeyEntry secretKeyEntry = new SecretKeyEntry(key);
            ProtectionParameter entryPassword = new PasswordProtection(KEY_STORE_PASSWORD);
            keyStore.setEntry(entryName, secretKeyEntry, entryPassword);
        
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new CryptoException("Error storing symmetric key", e);
        }
    }

    private SecretKey generateKey() throws CryptoException {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(KEY_SIZE, new SecureRandom());

            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Error generating symmetric key", e);
        }
        
    }

    public static void main(String[] args) throws CryptoException {
        CryptoUtils cryptoUtils = new CryptoUtils();
        File file = new File("C:\\Users\\jvsfc\\Desktop\\jFSTMerge\\src\\main\\java\\br\\ufpe\\cin\\crypto\\FilesEncoding.java");
        cryptoUtils.cipher(file, file);
    }
    
}

