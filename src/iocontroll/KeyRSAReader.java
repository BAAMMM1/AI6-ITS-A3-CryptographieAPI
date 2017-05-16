package iocontroll;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyRSAReader {

	private final static String ALGORITHM_RSA = "RSA";
	private KeyFactory keyFactory;

	public KeyRSAReader() throws NoSuchAlgorithmException   {
		keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
	}


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
	
	public Key readRSAKey(String path) throws InvalidKeySpecException, IOException{
		String fileExtention = path.substring(path.indexOf("."));
		
		if(fileExtention.equals(".pub")){			
			// Der öffentliche Schlüssel liegt im X.509-Format vor
			return keyFactory.generatePublic(new X509EncodedKeySpec(this.readKeyFile(path)));
			
		} else if(fileExtention.equals(".prv")){			
			// Der private Schlüssel liegt im PKCS8-Format vor
			return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(this.readKeyFile(path)));
			
		} else {
			throw new IllegalArgumentException("only typ .pub or .prv accepted");
		}
	}


}
