package iocontroll;

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
	private byte[] encryptedFile;

	public SecureFileReader(String path) throws IOException {
		this.readSecureFile(path);
	}

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

		// 7. Verschlüsselte Dateidaten
		this.encryptedFile = new byte[inStream.available()];

		inStream.read(this.encryptedFile);

		inStream.close();
	}

	public byte[] getEncryptKeyAES() {
		return this.encryptKeyAES;
	}

	public byte[] getSignatureKeyAES() {
		return this.signatureKeyAES;
	}

	public byte[] getEncryptedFile() {
		return this.encryptedFile;
	}

}
