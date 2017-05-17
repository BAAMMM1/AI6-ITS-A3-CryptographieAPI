package model.iocontroll.writer;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileWriter {

	public FileWriter() {
	}

	/**
	 * Schreibt ein Abfolge von Bytes in eine Datei
	 * @param file Zuschreibene Dateibytes
	 * @param path Ziel
	 * @throws IOException
	 */
	public void writeFile(byte[] file, String path) throws IOException {
		DataOutputStream outStream;

		outStream = new DataOutputStream(new FileOutputStream(path));

		outStream.write(file);

		outStream.close();

	}

}
