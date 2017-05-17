package model.receiveSecureFile;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
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

import model.iocontroll.reader.KeyRSAReader;
import model.iocontroll.reader.SecureFileReader;
import model.iocontroll.writer.FileWriter;
import utility.Printer;
import utility.ByteUtility;

/**
 * Diese Klasse liest einen öffentlichen RSA‐Schlüssels und einen privaten
 * RSA‐Schlüssels aus einer Datei ein.
 * 
 * DesWeiteren wird eine .ssf‐Datei eingelesen. In der .ssf Datei befindet sich:
 * 
 * 1. Ein verschlüsselter geheimee AES-Schlüssel. * 2. Die Signature des
 * geheimen Schlüssel. * 3. Algorithmische Parameter des geheimen Schüssels * 4.
 * Sowie die Verschlüsselte Dateidaten
 * 
 * Der geheime AES-Schlüssel wird mit dem privaten RSA‐Schlüssel entschlüsset
 * und die die Dateidaten werde mit dem geheimen Schlüssel (AES im Counter‐Mode)
 * – mit Anwendung der übermittelten algorithmischen Parameter – entschlüsselt.
 * 
 * Anschließend werden die entschlüsselten Dateidaten in einer
 * Klartext‐Ausgabedatei ausgegeben
 * 
 * Zum Schluß wird die Signatur für den geheimen AES-Schlüssel mit dem
 * öffentlichen RSA‐Schlüssel (Algorithmus: „SHA256withRSA“) überprüft.
 */
public class RSF {

	private final static String ALGORITHM_AES = "AES";
	private final static String ALGORITHM_AES_CTR = "AES/CTR/NoPadding";
	private final static String ALGORITHM_RSA = "RSA";
	private final static String ALGORITHM_SIGNATURE = "SHA256withRSA";

	public RSF() {

	}

	/**
	 * Diese Mehtode liest die .ssf Datei und entschlüsselt die übergebene
	 * Datei.
	 * 
	 * @param privateKey
	 *            PrivateKey des Empfängers
	 * @param publicKey
	 *            PublicKey des Senders
	 * @param fileIn
	 *            Zuentschlüsselne Datei
	 * @param fileOut
	 *            Ausgabedatei
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 */
	public void receiveSecureFile(String privateKey, String publicKey, String fileIn, String fileOut)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException,
			InvalidAlgorithmParameterException {

		KeyRSAReader readerKeyRSA = new KeyRSAReader();
		SecureFileReader secureFileReader = new SecureFileReader(fileIn);
		FileWriter writerFile = new FileWriter();

		// a. Einlesen eines öffentlichen RSA‐Schlüssels aus einer Datei
		PublicKey keyRSAPub = (PublicKey) readerKeyRSA.readRSAKey(publicKey);

		// b. Einlesen eines privaten RSA‐Schlüssels aus einer Datei
		PrivateKey keyRSAPrv = (PrivateKey) readerKeyRSA.readRSAKey(privateKey);

		// c. 1. Einlesen einer .ssf‐Datei
		byte[] signatureKeyAES = secureFileReader.getSignatureKeyAES();
		byte[] encryptedKeyAES = secureFileReader.getEncryptKeyAES();
		byte[] algorithmParameters = secureFileReader.getAlgorithmParameters();
		byte[] encryptedFile = secureFileReader.getEncryptedFile();

		// c. 2. Entschlüsselung des geheimen Schlüssels mit dem privaten
		// RSA‐Schlüssel,
		byte[] decryptedKeyAES = this.decryptKeyAES(encryptedKeyAES, keyRSAPrv);

		// c. 3. Entschlüsselung der Dateidaten mit dem geheimen Schlüssel (AES
		// im Counter‐Mode) – mit Anwendung der übermittelten algorithmischen
		// Parameter –
		byte[] decryptedFile = this.decryptedFile(decryptedKeyAES, algorithmParameters, encryptedFile);

		// c. 4. Erzeugung einer Klartext‐Ausgabedatei.
		writerFile.writeFile(decryptedFile, fileOut);

		// Überprüfung der Signatur für den geheimen Schlüssel mit dem
		// öffentlichen RSA‐Schlüssel
		if (!this.validSignature(keyRSAPub, decryptedKeyAES, signatureKeyAES)) {
			throw new IllegalArgumentException("signature incorrect");
		} else {
			Printer.prompt(this, "signature correct");
		}

	}

	/**
	 * Diese Mehtode entschlüsselte mit hilfe des entschlüsselten AES-Schlüssel
	 * und den Algorithmischen-Parameter des AES-Schlüssel die verschlüsselten
	 * Dateidaten.
	 * 
	 * @param decryptedKeyAES
	 *            entschlüsselterr AES-Schlüssel
	 * @param algorithmParameters
	 *            Algorithmischen-Parameter des AES-Schlüssel
	 * @param encryptedFile
	 *            verschlüsselte Dateidaten
	 * @return Entschlüsselte Dateidaten
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
	 */
	private byte[] decryptedFile(byte[] decryptedKeyAES, byte[] algorithmParameters, byte[] encryptedFile)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, IOException, InvalidAlgorithmParameterException {

		SecretKeySpec secretKeySpec = new SecretKeySpec(decryptedKeyAES, ALGORITHM_AES);

		AlgorithmParameters algorithmParms = AlgorithmParameters.getInstance(ALGORITHM_AES);

		algorithmParms.init(algorithmParameters);

		Cipher cipher = Cipher.getInstance(ALGORITHM_AES_CTR);

		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, algorithmParms);

		return ByteUtility.concatenate(cipher.update(encryptedFile), cipher.doFinal());
	}

	/**
	 * Diese Mehtode entschlüsselt den verschlüsselten AES-Schlüssel mit hilfe
	 * des PrivateKeys des Empfängers.
	 * 
	 * @param encryptedKeyAES
	 *            Vershlüsselter AES-Schlüssel
	 * @param keyRSAPrv
	 *            PrivateKeys des Empfängers
	 * @return Entschlüsselter AES-Schlüssel
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private byte[] decryptKeyAES(byte[] encryptedKeyAES, PrivateKey keyRSAPrv) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = Cipher.getInstance(ALGORITHM_RSA);

		cipher.init(Cipher.DECRYPT_MODE, keyRSAPrv);

		return ByteUtility.concatenate(cipher.update(encryptedKeyAES), cipher.doFinal());
	}

	/**
	 * Diese Mehtode überprüft ob der Schlüssel valid ist
	 * 
	 * @param keyRSAPub
	 *            PublicKey
	 * @param decryptedKeyAES
	 *            Entschlüsselter AES-Schlüssel
	 * @param signature
	 *            Signatur für den entschlüsselten AES-Schlüssel
	 * @return falls Signature ok, dann true
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
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
				Printer.error("Falscher Algorithmus", e);

			} catch (NoSuchAlgorithmException e) {
				Printer.error("Es existiert keine Implementierung fuer RSA", e);

			} catch (SignatureException e) {
				Printer.error("Fehler beim ueberpruefen der Signatur", e);

			} catch (NoSuchPaddingException e) {
				Printer.error("Fehler beim Padding", e);

			} catch (IllegalBlockSizeException e) {
				Printer.error("Fehler beim der BlockSize", e);

			} catch (BadPaddingException e) {
				Printer.error("Fehler beim der Padding", e);

			} catch (InvalidKeySpecException e) {
				Printer.error("Fehler beim Konvertieren des Schluessels", e);

			} catch (IOException e) {
				Printer.error("Datei-Fehler beim Lesen oder schreiben", e);

			} catch (InvalidAlgorithmParameterException e) {
				Printer.error("Algorithmen-Parameter nicht korrekt", e);

			}

		} else {
			throw new IllegalArgumentException("Erlaubte Argumente: <privateKey> <publicKey> <fileIn> <filOut>");
		}
	}

	@Override
	public String toString() {
		return String.format("RSF");
	}

}
