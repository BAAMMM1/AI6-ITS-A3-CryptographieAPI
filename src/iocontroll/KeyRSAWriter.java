package iocontroll;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Diese Klasse ist dafür zuständig ein Key in eine Datei zuschreiben. Der Name
 * der Ausgabedatei ist davon abhängig ob ein Public- oder Private-Key übergeben
 * wird und dem Name des Inhaber des Schlüssels.
 */
public class KeyRSAWriter {

	private final static String PATH = "";
	private final static String FILE_EXTENTION_PUBIC = ".pub";
	private final static String FILE_EXTENTION_PRIVATE = ".prv";

	public KeyRSAWriter() {

	}

	/**
	 * Diese Methode erlaubt es einen Schluessel in einem File abzuspeichern.
	 * 
	 * @param key
	 *            PublicKey or PrivateKey
	 * @param fileName
	 *            Inhaber-Name
	 * @throws IOException
	 */
	public void write(Key key, String fileName) throws IOException {
		// precondition test
		// Ist der key nicht null

		DataOutputStream outStream = new DataOutputStream(new FileOutputStream(this.getFilePath(key, fileName)));

		byte[] keyBytes = key.getEncoded();

		// 1. Länge des Inhaber-Namens
		outStream.writeInt(fileName.length());

		// 2. Inhaber-Name
		outStream.write(fileName.getBytes());

		// 3.Länge des Schlüssels
		outStream.writeInt(keyBytes.length);

		// 4. Schlüssel
		outStream.write(keyBytes);

		outStream.close();
	}

	/**
	 * Diese Mehtode ermittelt die Dateiendungen für den Dateinamen. Der
	 * Dateinamen ist von der Art des Keys abhängig.
	 * 
	 * @param key
	 *            PublicKey or PrivateKey
	 * @param fileName
	 * @return path for the key to save
	 */
	private String getFilePath(Key key, String fileName) {
		if (key instanceof PublicKey) {
			return PATH + fileName + FILE_EXTENTION_PUBIC;
		} else if (key instanceof PrivateKey) {
			return PATH + fileName + FILE_EXTENTION_PRIVATE;
		} else {
			throw new IllegalArgumentException("only <PublicKey> oder <PrivateKey> accepted");
		}
	}

}
