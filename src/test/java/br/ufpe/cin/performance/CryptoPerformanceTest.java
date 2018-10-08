package br.ufpe.cin.performance;

import static org.assertj.core.api.Assertions.*;

import java.io.File;
import java.io.OutputStream;
import java.io.PrintStream;

import br.ufpe.cin.crypto.CryptoUtils;
import br.ufpe.cin.exceptions.CryptoException;
import org.junit.*;

import br.ufpe.cin.app.JFSTMerge;

public class CryptoPerformanceTest {

	private static final int NUM_ITERATIONS = 6;
	private static final double ACCEPTED_MARGIN = 0.4;
	
	@BeforeClass
	public static void setUpBeforeClass() {
		//hidding sysout output
		@SuppressWarnings("unused")
		PrintStream originalStream = System.out;
		PrintStream hideStream    = new PrintStream(new OutputStream(){
			public void write(int b) {}
		});
		System.setOut(hideStream);
    }

    @Before
	public void decryptFiles() {
		try {
			decrypt("jfstmerge.statistics");
			decrypt("jfstmerge.files");
		} catch (CryptoException e) {
			// The files are already decrypted.
			System.out.println("Cryptography performance test: the files are already decrypted. Proceeding normally.");
		}
	}
		
	@Test
	public void testPerformanceWithDeletion() {

		JFSTMerge.isCryptographed = false;
		long noCryptoMean = computeMeanTimeOfMergeProcedure("testfiles/deletioninnerinleft");

		JFSTMerge.isCryptographed = true;
		long cryptoMean = computeMeanTimeOfMergeProcedure("testfiles/deletioninnerinleft");

		assertThat((double) (cryptoMean - noCryptoMean)).isLessThanOrEqualTo(ACCEPTED_MARGIN * noCryptoMean);
	}

	@Test
	public void testPerformanceWithDuplications() {

		JFSTMerge.isCryptographed = false;
		long noCryptoMean = computeMeanTimeOfMergeProcedure("testfiles/duplicationsconflicting");

		JFSTMerge.isCryptographed = true;
		long cryptoMean = computeMeanTimeOfMergeProcedure("testfiles/duplicationsconflicting");

		assertThat((double) (cryptoMean - noCryptoMean)).isLessThanOrEqualTo(ACCEPTED_MARGIN * noCryptoMean);
	}

	@Test
	public void testPerformanceWithInitializations() {

		JFSTMerge.isCryptographed = false;
		long noCryptoMean = computeMeanTimeOfMergeProcedure("testfiles/initlblocksnobase");

		JFSTMerge.isCryptographed = true;
		long cryptoMean = computeMeanTimeOfMergeProcedure("testfiles/initlblocksnobase");

		assertThat((double) (cryptoMean - noCryptoMean)).isLessThanOrEqualTo(ACCEPTED_MARGIN * noCryptoMean);
	}

	@Test
	public void testPerformanceWithNewReferencing() {

		JFSTMerge.isCryptographed = false;
		long noCryptoMean = computeMeanTimeOfMergeProcedure("testfiles/nereomethodfield");

		JFSTMerge.isCryptographed = true;
		long cryptoMean = computeMeanTimeOfMergeProcedure("testfiles/nereomethodfield");

		assertThat((double) (cryptoMean - noCryptoMean)).isLessThanOrEqualTo(ACCEPTED_MARGIN * noCryptoMean);
	}

	@Test
	public void testPerformanceWithRenaming() {

		JFSTMerge.isCryptographed = false;
		long noCryptoMean = computeMeanTimeOfMergeProcedure("testfiles/renaminginright");

		JFSTMerge.isCryptographed = true;
		long cryptoMean = computeMeanTimeOfMergeProcedure("testfiles/renaminginright");

		assertThat((double) (cryptoMean - noCryptoMean)).isLessThanOrEqualTo(ACCEPTED_MARGIN * noCryptoMean);
	}

	private long computeMeanTimeOfMergeProcedure(String testFilesDirectory) {
		long initialTime, finalTime, totalTime = 0;

		for(int i = 0; i < NUM_ITERATIONS; i++) {

			initialTime = System.currentTimeMillis();
			new JFSTMerge().mergeFiles(
					new File(testFilesDirectory + "/left/Test.java"),
					new File(testFilesDirectory + "/base/Test.java"),
					new File(testFilesDirectory + "/right/Test.java"),
					null);
			finalTime = System.currentTimeMillis();

			totalTime += finalTime - initialTime;
		}

		return totalTime / NUM_ITERATIONS;
	}

	private static void decrypt(String fileName) throws CryptoException {
		String logPath = System.getProperty("user.home") + File.separator + ".jfstmerge" + File.separator + fileName;

		File file = new File(logPath);
		CryptoUtils.decrypt(file, file);

	}

	private long computeMeanTimeOfMergeProcedure(int testCase) {
		long totalTime = 0;
		for(int i = 0; i < NUM_ITERATIONS; i++) {
			long initialTime = System.currentTimeMillis();

			new JFSTMerge().mergeFiles(
					new File("testfiles/cryptoperformance/test" + testCase + "/left.java"),
					new File("testfiles/cryptoperformance/test" + testCase + "/base.java"),
					new File("testfiles/cryptoperformance/test" + testCase + "/right.java"),
					null);

			long finalTime = System.currentTimeMillis();
			totalTime += finalTime - initialTime;

		}

		return totalTime / NUM_ITERATIONS;
	}

    private static File getLogPath(String file) {
        return new File(System.getProperty("user.home") + File.separator + ".jfstmerge" + File.separator + file);
    }

    private static void renameFile(String file1, String file2) throws Exception {
        File logPath   = getLogPath(file1);
        File logCopyPath = getLogPath(file2);
        Files.move(logPath.toPath(), logCopyPath.toPath(), REPLACE_EXISTING);
    }
	
}
