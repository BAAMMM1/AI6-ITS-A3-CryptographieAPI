package iocontroll;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class FileReader {

	public FileReader() {
	}

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
