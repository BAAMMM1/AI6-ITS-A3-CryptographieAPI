package keyRSACreation;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import iocontroll.KeyRSAWriter;

/**
 * Diese Klasse erzeugt ein RSA-Schluesselpaar (Schluessellaenge: 2048 Bit),
 * welche in einer Datei gespeichert werden. Der Name des Inhaber des
 * Schlüsselpaares wird in der Kommandozeile mit übergeben.
 */
public class RSAKeyCreation {

	private final static String ALGORITHM_RSA = "RSA";
	private final static int KEY_RSA_LENGTH = 2048;

	private KeyRSAWriter keyWriter;

	public RSAKeyCreation() {
		this.keyWriter = new KeyRSAWriter();
	}

	/**
	 * Diese Methode erzeugt eine Public-/Private-Keypaar des Typs RSA und
	 * schreibt es in eine Datei.
	 * 
	 * @param ownerName
	 *            Name des Besitzter der Keys
	 * @throws NoSuchAlgorithmException
	 *             Falls der RSA Algorithmus nicht gefunden werden kann
	 * @throws IOException
	 *             Falls die Datei nicht geschrieben werden kann
	 */
	public void createKeyPeer(String ownerName) throws NoSuchAlgorithmException, IOException {		
		/*
		 * 1. Erstellung eines Public-/Private-Key-Paares
		 */		
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA);

		generator.initialize(KEY_RSA_LENGTH);

		KeyPair keyPair = generator.genKeyPair();

		/*
		 * 2. Speicherung des Public- und Private-Key
		 * Format: PublicKey: X.509, PrivateKey: PKCS#8
		 */
		this.keyWriter.write(keyPair.getPublic(), ownerName);
		this.keyWriter.write(keyPair.getPrivate(), ownerName);

	}

	/**
	 * Der Name des Inhaber wird als Argument in der Kommandozeile übergeben.
	 * 
	 * @param args
	 *            [0]=Inhabername
	 */
	public static void main(String[] args) {

		if (args.length == 1) {

			try {

				RSAKeyCreation rsaKeyCreation = new RSAKeyCreation();
				rsaKeyCreation.createKeyPeer(args[0]);

			} catch (NoSuchAlgorithmException e) {
				System.out.println("error: algorithm not found");

			} catch (IOException e) {
				System.out.println("error: output");
			}

		} else {
			throw new IllegalArgumentException("valid argument: <inhabername>");
		}
	}

}
