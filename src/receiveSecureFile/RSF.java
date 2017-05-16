package receiveSecureFile;

import java.io.IOException;
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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import iocontroll.FileWriter;
import iocontroll.KeyRSAReader;
import iocontroll.SecureFileReader;

public class RSF {

	private final static String ALGORITHM_AES = "AES";
	private final static String ALGORITHM_RSA = "RSA";
	private final static String ALGORITHM_SIGNATURE = "SHA256withRSA";

	public RSF() {

	}

	public void receiveSecureFile(String privateKey, String publicKey, String fileIn, String fileOut)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException {

		KeyRSAReader readerKeyRSA = new KeyRSAReader();
		SecureFileReader secureFileReader = new SecureFileReader(fileIn);
		FileWriter writerFile = new FileWriter();

		PublicKey keyRSAPub = (PublicKey) readerKeyRSA.readRSAKey(publicKey);
		PrivateKey keyRSAPrv = (PrivateKey) readerKeyRSA.readRSAKey(privateKey);

		byte[] signatureKeyAES = secureFileReader.getSignatureKeyAES();
		byte[] encryptedKeyAES = secureFileReader.getEncryptKeyAES();
		byte[] encryptedFile = secureFileReader.getEncryptedFile();

		byte[] decryptedKeyAES = this.decryptKeyAES(encryptedKeyAES, keyRSAPrv);
		byte[] decryptedFile = this.decryptedFile(decryptedKeyAES, encryptedFile);

		if (!this.validSignature(keyRSAPub, decryptedKeyAES, signatureKeyAES)) {
			throw new IllegalArgumentException("signature uncorrect");
		}

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

	private boolean validSignature(PublicKey keyRSAPub, byte[] decryptedKeyAES, byte[] signature)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature rsaSignature = Signature.getInstance(ALGORITHM_SIGNATURE);

		rsaSignature.initVerify(keyRSAPub);

		rsaSignature.update(decryptedKeyAES);

		return rsaSignature.verify(signature);
	}

	public static void main(String[] args) {

		if (args.length == 4) {

			try {

				RSF rsf = new RSF();
				rsf.receiveSecureFile(args[0], args[1], args[2], args[3]);

			} catch (InvalidKeyException e) {

			} catch (NoSuchAlgorithmException e) {

			} catch (SignatureException e) {

			} catch (NoSuchPaddingException e) {

			} catch (IllegalBlockSizeException e) {

			} catch (BadPaddingException e) {

			} catch (InvalidKeySpecException e) {

			} catch (IOException e) {

			}

		} else {
			throw new IllegalArgumentException("valid argument: <privateKey> <publicKey> <fileIn> <filOut>");
		}

	}

}
