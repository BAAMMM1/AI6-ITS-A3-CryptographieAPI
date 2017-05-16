package receiveSecureFile;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import iocontroll.FileWriter;
import iocontroll.KeyRSAReader;
import iocontroll.SecureFileReader;
import sendSecureFile.SSF;

public class RSF {

	private final static String ALGORITHM_AES = "AES";
	private final static String ALGORITHM_RSA = "RSA";
	private final static int KEY_AES_LENGTH = 128;

	public RSF() {

	}

	public void receiveSecureFile(String privateKey, String publicKey, String fileIn, String fileOut) throws Exception {
		KeyRSAReader readerKeyRSA = new KeyRSAReader();
		System.out.println("secureFileReader");
		SecureFileReader secureFileReader = new SecureFileReader(fileIn);
		FileWriter writerFile = new FileWriter();

		PublicKey keyRSAPub = (PublicKey) readerKeyRSA.readRSAKey(publicKey);
		PrivateKey keyRSAPrv = (PrivateKey) readerKeyRSA.readRSAKey(privateKey);

		byte[] signatureKeyAES = secureFileReader.getSignatureKeyAES();
		byte[] encryptedKeyAES = secureFileReader.getEncryptKeyAES();
		byte[] encryptedFile = secureFileReader.getEncryptedFile();

		byte[] decryptedKeyAES = this.decryptKeyAES(encryptedKeyAES, keyRSAPrv);
		byte[] decryptedFile = this.decryptedFile(decryptedKeyAES, encryptedFile);
		
		// Signatur prüfen
		
		writerFile.writeFile(decryptedFile, fileOut);

	}

	private byte[] decryptedFile(byte[] decryptedKeyAES, byte[] encryptedFile) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
		SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedKeyAES, ALGORITHM_AES);

		// cipher.init(Cipher.DECRYPT_MODE, keyAES);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

		return cipher.doFinal(encryptedFile);

	}

	private byte[] decryptKeyAES(byte[] encryptedKeyAES, PrivateKey keyRSAPrv) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(ALGORITHM_RSA);

		cipher.init(Cipher.DECRYPT_MODE, keyRSAPrv);

		return cipher.doFinal(encryptedKeyAES);
	}

	public static void main(String[] args) throws Exception {

		if (args.length == 4) {
			RSF rsf = new RSF();
			rsf.receiveSecureFile(args[0], args[1], args[2], args[3]);
		} else {
			throw new IllegalArgumentException("valid argument: <privateKey> <publicKey> <fileIn> <filOut>");
		}

	}

}
