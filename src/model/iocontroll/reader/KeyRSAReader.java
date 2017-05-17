package model.iocontroll.reader;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Diese Klasse ist dafür zuständig ein Public- oder Private-Key mit dem
 * Algorithmus "RSA" einzulesen und zurückzugeben *
 */
public class KeyRSAReader {

	private final static String ALGORITHM_RSA = "RSA";
	private KeyFactory keyFactory;

	/**
	 * Erstell einen KeyRSAReader mit einer KeyFactory, die dafür zustöndig ist,
	 * einen PublicKey oder PrivateKey zuerstellen.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	public KeyRSAReader() throws NoSuchAlgorithmException {
		keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
	}

	/**
	 * Liest aus einem übergebenen Path einen Public- oder Private-Key ein und
	 * gibt ihn zurück. PublicKey werden im X.509-Format und PrivateKey im
	 * PKCS8-Format zurückgeben.
	 * 
	 * @param path
	 *            Dateipfad
	 * @return Public- oder Private-Key
	 * @throws InvalidKeySpecException
	 *             Falls Format nicht gefunden werden kann
	 * @throws IOException
	 *             Falls Datei nicht gefunden wird
	 */
	public Key readRSAKey(String path) throws InvalidKeySpecException, IOException {
		String fileExtention = path.substring(path.indexOf("."));

		if (fileExtention.equals(".pub")) {
			// Der öffentliche Schlüssel liegt im Zertifikat X.509-Format vor
			return keyFactory.generatePublic(new X509EncodedKeySpec(this.readKeyFile(path)));

		} else if (fileExtention.equals(".prv")) {
			// Der private Schlüssel liegt im Spezifikations PKCS8-Format vor
			return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(this.readKeyFile(path)));

		} else {
			throw new IllegalArgumentException("only typ .pub or .prv accepted");
		}
	}

	/**
	 * Liest einen Key aus einer Datei
	 * 
	 * @param path
	 *            Dateipfad
	 * @return Key als byte[]
	 * @throws IOException
	 *             Falls Datei nicht gefunden wird
	 */
	private byte[] readKeyFile(String path) throws IOException {

		byte[] ownerName;
		byte[] key;

		DataInputStream inStream;

		inStream = new DataInputStream(new FileInputStream(path));

		// Länge des Owners ermitteln
		// Owner aus der Datei lesen
		ownerName = new byte[inStream.readInt()];
		inStream.read(ownerName);

		// Länge des Schlüssels ermitteln
		// Schlüssel aus der Datei lesen
		key = new byte[inStream.readInt()];
		inStream.read(key);

		inStream.close();

		return key;

	}

}
