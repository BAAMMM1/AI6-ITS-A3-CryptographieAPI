package sendSecureFile;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import iocontroll.FileReader;
import iocontroll.FileWriter;
import iocontroll.KeyRSAReader;

public class SSF {

	private final static String ALGORITHM_AES = "AES";
	private final static String ALGORITHM_RSA = "RSA";
	private final static String ALGORITHM_SIGNATURE = "SHA256withRSA";
	private final static String FILE_EXTENTION = ".ssf";
	private final static int KEY_AES_LENGTH = 128;

	public SSF() {

	}

	public void sendSecureFile(String privateKey, String publicKey, String fileIn, String fileOut)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException,
			SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		KeyRSAReader readerKeyRSA = new KeyRSAReader();
		FileReader readerFile = new FileReader();
		FileWriter writerFile = new FileWriter();

		PublicKey keyRSAPub = (PublicKey) readerKeyRSA.readRSAKey(publicKey);
		PrivateKey keyRSAPrv = (PrivateKey) readerKeyRSA.readRSAKey(privateKey);

		SecretKey keyAES = this.generateAESKey();

		byte[] signatureKeyAES = this.generateSignaturForKeyAES(keyAES, keyRSAPrv);

		byte[] encryptedKeyAES = this.encryptKeyAES(keyAES, keyRSAPub);

		byte[] encryptedFile = this.encryptFile(readerFile.readFile(fileIn), keyAES);

		byte[] outputFile = this.createOutputFile(encryptedKeyAES, signatureKeyAES, encryptedFile);

		writerFile.writeFile(outputFile, fileOut + FILE_EXTENTION);

	}

	// c.
	private SecretKey generateAESKey() throws NoSuchAlgorithmException {
		
		KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM_AES);
		generator.init(KEY_AES_LENGTH);
		return generator.generateKey();
	}

	// d.
	private byte[] generateSignaturForKeyAES(SecretKey keyAES, PrivateKey keyRSAPrv)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature rsaSignature = Signature.getInstance(ALGORITHM_SIGNATURE);
		rsaSignature.initSign(keyRSAPrv);
		rsaSignature.update(keyAES.getEncoded());

		return rsaSignature.sign();

	}

	// e.
	private byte[] encryptKeyAES(SecretKey keyAES, PublicKey keyRSAPub) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipherRSA = Cipher.getInstance(ALGORITHM_RSA);
		cipherRSA.init(Cipher.ENCRYPT_MODE, keyRSAPub);

		return cipherRSA.doFinal(keyAES.getEncoded());
	}

	// f.
	private byte[] encryptFile(byte[] file, SecretKey keyAES) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipherAES = Cipher.getInstance(ALGORITHM_AES);
		cipherAES.init(Cipher.ENCRYPT_MODE, keyAES);

		return cipherAES.doFinal(file);
	}

	private byte[] createOutputFile(byte[] encryptKeyAES, byte[] signatureKeyAES, byte[] encryptedFile) {

		ByteBuffer bb = ByteBuffer.allocate(8 + encryptKeyAES.length + signatureKeyAES.length + encryptedFile.length);
		
		// 1. Länge des verschlüsselten geheimen Schlüssels
		bb.putInt(encryptKeyAES.length);
		
		// 2. Verschlüsselter geheimer Schlüssel
		bb.put(encryptKeyAES);
		
		// 3. Länge der Signature des geheimen Schlüssel
		bb.putInt(signatureKeyAES.length);
		
		// 4. Signature des geheimen Schlüssels
		bb.put(signatureKeyAES);
		
		// 5. Länge der algorithmischen Parameter des geheimen Schlüssel

		// 6. Algorithmische Parameter des geheimen Schüssels

		// 7. Verschlüsselte Dateidaten
		bb.put(encryptedFile);

		return bb.array();
	}

	public static void main(String[] args) {

		if (args.length == 4) {
			
			try {
				SSF sff = new SSF();
				
				sff.sendSecureFile(args[0], args[1], args[2], args[3]);
				
			} catch (InvalidKeyException e) {

			} catch (NoSuchAlgorithmException e) {
				
			} catch (InvalidKeySpecException e) {
				
			} catch (SignatureException e) {
				
			} catch (NoSuchPaddingException e) {
				
			} catch (IllegalBlockSizeException e) {
				
			} catch (BadPaddingException e) {
				
			} catch (IOException e) {
				
			}
			
		} else {
			throw new IllegalArgumentException("valid argument: <privateKey> <publicKey> <fileIn> <filOut>");
		}

	}

}
