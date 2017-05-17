package iocontroll;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileWriter {

	public FileWriter() {
	}

	public void writeFile(byte[] file, String path) throws IOException {
		DataOutputStream outStream;

		outStream = new DataOutputStream(new FileOutputStream(path));

		outStream.write(file);

		outStream.close();

	}

}
