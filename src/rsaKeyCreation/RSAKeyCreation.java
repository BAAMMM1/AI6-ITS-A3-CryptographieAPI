package rsaKeyCreation;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import ioControll.KeyWriter;

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
	
	private final static String PATH = "res/keys/";
	private final static String FILE_EXTENTION_PUBIC = ".pub";
	private final static String FILE_EXTENTION_PRIVATE = ".prv";
	private final static String ALGORITHM = "RSA";
	private final static int KEY_LENGTH = 2048;
	
	private KeyWriter keyWriter;
	
	public RSAKeyCreation() {
		this.keyWriter = new KeyWriter();
	}
	
	
	public void createKeyPeer(String fileName) throws NoSuchAlgorithmException, IOException{
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
		generator.initialize(KEY_LENGTH);
		
		KeyPair keyPair = generator.genKeyPair();
			
		this.keyWriter.writeFileBlockList(keyPair.getPublic(), PATH + fileName + FILE_EXTENTION_PUBIC);
		this.keyWriter.writeFileBlockList(keyPair.getPrivate(), PATH + fileName + FILE_EXTENTION_PRIVATE);
		
	}	
	
	public static void main(String[] args) {
		
		if(args.length == 1){
			RSAKeyCreation rsaKeyCreation = new RSAKeyCreation();
			try {
				rsaKeyCreation.createKeyPeer(args[0]);
			} catch (NoSuchAlgorithmException | IOException e) {
				e.printStackTrace();
			}
			
		} else {
			throw new IllegalArgumentException("valid argument: <inhabername>");
		}
		

	}

	
	

}
