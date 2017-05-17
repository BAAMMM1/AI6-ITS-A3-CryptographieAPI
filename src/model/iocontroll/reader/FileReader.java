package model.iocontroll.reader;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class FileReader {

	public FileReader() {
	}

	/**
	 * Liest ein Abfolge von Bytes aus einer Datei
	 * @param path Dateipfad der Datei
	 * @return byte[] welches die Datei repräsentiert
	 * @throws IOException
	 */
	public byte[] readFile(String path) throws IOException {
		byte[] buffer = null;
		DataInputStream inStream;

		inStream = new DataInputStream(new FileInputStream(path));

		buffer = new byte[inStream.available()];

		inStream.read(buffer);

		inStream.close();

		return buffer;
	}

}
