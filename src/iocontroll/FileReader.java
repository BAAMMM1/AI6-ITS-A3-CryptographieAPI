package iocontroll;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class FileReader {

	public FileReader() {
	}
	
	public byte[] readFile(String path) {	
		byte[] buffer = null;
		DataInputStream inStream;
		
		try {
			inStream = new DataInputStream(new FileInputStream(path));
			
			buffer = new byte[inStream.available()];
			
			inStream.read(buffer);
			
			inStream.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
		return buffer;
	}

}
