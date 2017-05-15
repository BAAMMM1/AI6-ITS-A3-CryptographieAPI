package ioControll;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;

public class KeyWriter {

	public KeyWriter() {
		
	}
	
	public void writeFileBlockList(Key key, String path) throws IOException {
		DataOutputStream outStream;

		outStream = new DataOutputStream(new FileOutputStream(path));

		byte[] toWriteBytes = key.getEncoded();

		outStream.write(toWriteBytes);
		outStream.close();
	}

}
