package br.ufpe.cin.unit;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import br.ufpe.cin.crypto.FileEncrypterDecrypter;
import br.ufpe.cin.exceptions.CryptoException;

/**
 * Unit tests for FileEncrypterDecrypter class.
 */
public class FileEncrypterDecrypterTest {

    private final Path keyStoreFilePath = Paths.get(System.getProperty("user.home"), "keystore.ks");
    private final Path tempKeyStoreFilePath = Paths.get(System.getProperty("user.home"), "keystore2.ks");

    private final Path targetFile = Paths.get("build.gradle");
    private final Path tempTargetFile = Paths.get("tempBuildEncrypted.gradle");

    private final FileEncrypterDecrypter fileEncrypterDecrypter = new FileEncrypterDecrypter();

    @Before
    public void renameKeyStoreFile() throws IOException {
        if (Files.exists(keyStoreFilePath)) {
            Files.move(keyStoreFilePath, tempKeyStoreFilePath);
        }
    }

    @After
    public void restoreKeyStoreFile() throws IOException {
        if (Files.exists(tempKeyStoreFilePath)) {
            Files.move(tempKeyStoreFilePath, keyStoreFilePath, StandardCopyOption.REPLACE_EXISTING);
        } else {
            Files.deleteIfExists(keyStoreFilePath);
        }
    }

    @Test
    public void testCryptography_whenEncryptingIntoFile_andDecryptingFileAgain_shouldResultInOriginalString()
            throws CryptoException, IOException {
    
        fileEncrypterDecrypter.cipher(targetFile.toFile(), tempTargetFile.toFile());
        fileEncrypterDecrypter.decipher(tempTargetFile.toFile(), tempTargetFile.toFile());

        String originalContent = FileUtils.readFileToString(targetFile.toFile());
        String contentAfterEncryptionAndDecryption = FileUtils.readFileToString(tempTargetFile.toFile());
        
        Files.delete(tempTargetFile);
        
        assertEquals(originalContent, contentAfterEncryptionAndDecryption);

    }

    @Test(expected = CryptoException.class)
    public void testCryptography_whenDecryptingPlainFile_shouldThrowCryptoException() throws CryptoException {
        fileEncrypterDecrypter.decipher(targetFile.toFile(), targetFile.toFile());
    }
    
}