package test;

import java.io.IOException;
import java.io.InputStream;

import java.io.File;

import model.keyRSACreation.RSAKeyCreation;
import model.receiveSecureFile.RSF;
import model.sendSecureFile.SSF;

public class Test {

	private static final String TEST_PATH_01 = "test/AB/";
	private static final String TEST_PATH_02 = "test/RSF/";

	public Test() {
	}

	public void testAB() {

		RSAKeyCreation.main(new String[] { TEST_PATH_01 + "KMueller" });

		RSAKeyCreation.main(new String[] { TEST_PATH_01 + "FMeier" });

		SSF.main(new String[] { TEST_PATH_01 + "KMueller.prv", TEST_PATH_01 + "FMeier.pub", TEST_PATH_01 + "Brief.pdf",
				TEST_PATH_01 + "Brief" });

		RSF.main(new String[] { TEST_PATH_01 + "FMeier.prv", TEST_PATH_01 + "KMueller.pub", TEST_PATH_01 + "Brief.ssf",
				TEST_PATH_01 + "BriefOut.pdf" });

	}

	public void testC() throws Exception {

		// Step 1.
		RSAKeyCreation.main(new String[] { "test/RSF/Christian" });

		SSF.main(new String[] { TEST_PATH_02 + "Christian.prv", TEST_PATH_02 + "Test.pub", TEST_PATH_02 + "fileIn.pdf",
				TEST_PATH_02 + "fileOutEncrypted" });

		// Step 2.
		// Quelle:
		// http://stackoverflow.com/questions/15218892/running-a-java-program-from-another-java-program
		ProcessBuilder pb = new ProcessBuilder("java", "RSFTest", "Test.prv", "Christian.pub", "fileOutEncrypted.ssf",
				"fileOutDeCrypted.pdf");
		pb.redirectError();
		pb.directory(new File(TEST_PATH_02));
		Process p = pb.start();
		InputStreamConsumer consumer = new InputStreamConsumer(p.getInputStream());

		consumer.start();

		consumer.join();

		System.out.println(consumer.getOutput());

	}

	public class InputStreamConsumer extends Thread {

		private InputStream is;
		private IOException exp;
		private StringBuilder output;

		public InputStreamConsumer(InputStream is) {
			this.is = is;
		}

		@Override
		public void run() {
			int in = -1;
			output = new StringBuilder(64);
			try {
				while ((in = is.read()) != -1) {
					output.append((char) in);
				}
			} catch (IOException ex) {
				ex.printStackTrace();
				exp = ex;
			}
		}

		public StringBuilder getOutput() {
			return output;
		}

		public IOException getException() {
			return exp;
		}
	}

	public static void main(String[] args) throws Exception {
		Test test = new Test();
		test.testAB();

	}

}
