package model.iocontroll.reader;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Diese Klasse liest eine .ssf Datei ein und ermöglicht es die einzelnen
 * Bestandteile wie z.B. den verschlüsselten AES-Schlüssel abzufragen.
 */
public class SecureFileReader {

	private byte[] encryptKeyAES;
	private byte[] signatureKeyAES;
	private byte[] algorithmParameters;
	private byte[] encryptedFile;

	public SecureFileReader(String path) throws IOException {
		this.readSecureFile(path);
	}

	/**
	 * Diese Mehtode liest eine .ssf Datei ein und speicher die einzelnen
	 * Bestandteile ab
	 * 
	 * @param path
	 *            Dateipfad
	 * @throws IOException
	 */
	private void readSecureFile(String path) throws IOException {
		DataInputStream inStream;

		inStream = new DataInputStream(new FileInputStream(path));

		// 1. Länge des verschlüsselten geheimen AES-Schlüssels
		// 2. Verschlüsselter geheimer AES-Schlüssel
		this.encryptKeyAES = new byte[inStream.readInt()];
		inStream.read(this.encryptKeyAES);

		// 3. Länge der Signature des geheimen Schlüssel
		// 4. Signature des geheimen Schlüssels
		this.signatureKeyAES = new byte[inStream.readInt()];
		inStream.read(this.signatureKeyAES);

		// 5. Länge der algorithmischen Parameter des geheimen Schlüssel
		// 6. Algorithmische Parameter des geheimen Schüssels
		this.algorithmParameters = new byte[inStream.readInt()];
		inStream.read(algorithmParameters);

		// 7. Verschlüsselte Dateidaten
		this.encryptedFile = new byte[inStream.available()];

		inStream.read(this.encryptedFile);

		inStream.close();
	}

	/**
	 * Diese Mehtode gibt den verschlüsselten AES-Schlüssel aus der .ssf Datei
	 * zurück
	 * 
	 * @returnVerschlüsselter AES-Schlüssel
	 */
	public byte[] getEncryptKeyAES() {
		return this.encryptKeyAES;
	}

	/**
	 * Diese Mehtode gibt die Signature für den entschlüsselten AES-Schlüssel
	 * der .ssf Datei zurück
	 * 
	 * @return Signature für den entschlüsselten AES-Schlüssel
	 */
	public byte[] getSignatureKeyAES() {
		return this.signatureKeyAES;
	}

	/**
	 * Diese Mehtode gibt gibt die verschlüsselten Dateidaten zurück.
	 * 
	 * @return Verschlüsselte Dateidaten
	 */
	public byte[] getEncryptedFile() {
		return this.encryptedFile;
	}

	/**
	 * Diese Mehtode gibt die Algorithmischen Parameter des Cipher der die
	 * Dateidaten mit dem ALGORITHM_AES_CTR verschlüsselt zurück
	 * 
	 * @return Algorithmischen Parameter des Cipher
	 */
	public byte[] getAlgorithmParameters() {
		return this.algorithmParameters;
	}

}
