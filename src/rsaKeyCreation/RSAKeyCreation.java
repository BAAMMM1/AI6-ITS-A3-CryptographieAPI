package rsaKeyCreation;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

import utility.IOController;

/*
 * Kann das hier eine SchluesselpaarFactory werden? bzw ein singleton?
 */
/**
 * Diese Klasse erzeugt ein RSA-Schluesselpaar (Schluessellaenge: 2048 Bit),
 * welche in einer Datei gespeichert werden. Der Name des Inhaber des
 * Schlüsselpaares wird in der Kommandozeile mit übergeben.
 * 
 */
public class RSAKeyCreation {	
	
	private IOController controller;
	private final static String PATH = "/keys/";
	private final static String FILE_EXTENTION_PUBIC = ".pub";
	private final static String FILE_EXTENTION_PRIVATE = ".prv";

	public RSAKeyCreation() {
		this.controller = new IOController();
	}
	
	
	public void createKeyPeer(String owner){
		
		this.createPublicKey(owner);
		this.createPrivateKey(owner);
		
	}
	
	// private Key
	/*
	 * Hier entstehen byte array, die als Datei über den IOController geschrieben werden
	 */
	private void createPublicKey(String owner){
		List<byte[]> toWriteLis = new LinkedList<byte[]>();
		
		byte[] lenghtOwner = ByteBuffer.allocate(4).putInt(owner.length()).array();
		byte[] ownerName = owner.getBytes();
		
		
		this.controller.writeFileBlockList(toWriteLis, PATH + owner + FILE_EXTENTION_PUBIC);
		
	}
	
	private void createPrivateKey(String owner){
		List<byte[]> toWriteLis = new LinkedList<byte[]>();
		
		
		this.controller.writeFileBlockList(toWriteLis, PATH + owner + FILE_EXTENTION_PRIVATE);
		
	}
	
	

}
