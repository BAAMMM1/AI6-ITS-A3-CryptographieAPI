package keyRSACreation;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import iocontroll.KeyWriter;

/**
 * Diese Klasse erzeugt ein RSA-Schluesselpaar (Schluessellaenge: 2048 Bit),
 * welche in einer Datei gespeichert werden. Der Name des Inhaber des
 * Schlüsselpaares wird in der Kommandozeile mit übergeben.
 */
public class RSAKeyCreation {

	private final static String ALGORITHM_RSA = "RSA";
	private final static int KEY_RSA_LENGTH = 2048;

	private KeyWriter keyWriter;

	public RSAKeyCreation() {
		this.keyWriter = new KeyWriter();
	}

	public void createKeyPeer(String ownerName) throws NoSuchAlgorithmException, IOException {
		/*
		 * 1. Erstellung eines Public-/Private-Key-Paares
		 */
		KeyPairGenerator generator;

		generator = KeyPairGenerator.getInstance(ALGORITHM_RSA);

		generator.initialize(KEY_RSA_LENGTH);

		KeyPair keyPair = generator.genKeyPair();

		/*
		 * 2. Speicherung des Public- und Private-Key
		 */
		this.keyWriter.write(keyPair.getPublic(), ownerName);
		this.keyWriter.write(keyPair.getPrivate(), ownerName);

	}

	public static void main(String[] args) {

		if (args.length == 1) {

			try {

				RSAKeyCreation rsaKeyCreation = new RSAKeyCreation();
				rsaKeyCreation.createKeyPeer(args[0]);

			} catch (NoSuchAlgorithmException e) {
				System.out.println("error: algorithm not found");

			} catch (IOException e) {
				System.out.println("error: input/output");
			}

		} else {
			throw new IllegalArgumentException("valid argument: <inhabername>");
		}
	}

}
