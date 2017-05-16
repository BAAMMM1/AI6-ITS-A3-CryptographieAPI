package iocontroll;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class SecureFileReader {
	
	private byte[] encryptKeyAES;
	private byte[] signatureKeyAES;
	private byte[] encryptedFile;

	public SecureFileReader(String path) throws Exception {
		this.readSecureFile(path);
	}

	private void readSecureFile(String path) throws IOException {
		DataInputStream inStream;

		inStream = new DataInputStream(new FileInputStream(path));

		int encryptKeyAESlenght = inStream.readInt();
		System.out.println(encryptKeyAESlenght);
		this.encryptKeyAES = new byte[encryptKeyAESlenght];
		inStream.read(this.encryptKeyAES);

		int signatureKeyAESLenght = inStream.readInt();
		System.out.println(signatureKeyAESLenght);
		this.signatureKeyAES = new byte[signatureKeyAESLenght];
		inStream.read(this.signatureKeyAES);
		
		// TODO Algorithmische Parameter

		this.encryptedFile = new byte[inStream.available()];
		inStream.read(this.encryptedFile);

		inStream.close();
	}
	
	public byte[] getEncryptKeyAES(){
		return this.encryptKeyAES;
	}
	
	public byte[] getSignatureKeyAES(){
		return this.signatureKeyAES;
	}
	
	public byte[] getEncryptedFile(){
		return this.encryptedFile;
	}

}
