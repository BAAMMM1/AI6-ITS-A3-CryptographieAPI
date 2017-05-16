package rsaKeyCreation;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import iocontroll.KeyWriter;

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
	
	private final static String ALGORITHM_RSA = "RSA";
	private final static int KEY_RSA_LENGTH = 2048;
	
	private KeyWriter keyWriter;
	
	public RSAKeyCreation() {
		this.keyWriter = new KeyWriter();
	}
	
	
	public void createKeyPeer(String fileName) throws NoSuchAlgorithmException, IOException{
		// precondition test
		// ist der owner Sring ok
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
		generator.initialize(KEY_RSA_LENGTH);
		
		KeyPair keyPair = generator.genKeyPair();
			
		this.keyWriter.write(keyPair.getPublic(), fileName);
		this.keyWriter.write(keyPair.getPrivate(), fileName);
		
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
