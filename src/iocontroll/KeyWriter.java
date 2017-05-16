package iocontroll;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyWriter {
	
	private final static String PATH = "";
	private final static String FILE_EXTENTION_PUBIC = ".pub";
	private final static String FILE_EXTENTION_PRIVATE = ".prv";

	public KeyWriter() {
		
	}
	
	public void write(Key key, String fileName) throws IOException {
		// precondition test
		// Ist der key nicht null
		
		DataOutputStream outStream;
		
		outStream = new DataOutputStream(new FileOutputStream(this.getFilePath(key, fileName)));		

		byte[] keyAsByteArray = key.getEncoded();
		
		outStream.writeInt(fileName.length());
		outStream.write(fileName.getBytes());
		outStream.writeInt(keyAsByteArray.length);
		outStream.write(keyAsByteArray);
		outStream.close();
	}
	
	private String getFilePath(Key key, String fileName){
		if(key instanceof PublicKey){
			return PATH + fileName + FILE_EXTENTION_PUBIC;
		} else if (key instanceof PrivateKey){
			return PATH + fileName + FILE_EXTENTION_PRIVATE;
		} else {
			return null;
		}
	}

}
