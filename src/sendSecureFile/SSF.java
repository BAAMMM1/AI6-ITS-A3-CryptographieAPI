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

/**
 * Die Klasse SSF („SendSecureFile“) liest einen privaten RSA‐Schlüssels (.prv)
 * und einen öffentlichen RSA‐Schlüssels (.pub) aus einer Datei ein.
 * 
 * Anschließend wird ein geheimener Schlüssels für den AES‐Algorithmus mit der
 * Schlüssellänge 128 Bit erzeugt.
 * 
 * Des Weiteren wird eine Signatur für den geheimen AES-Schlüssel mit dem
 * privaten RSA‐Schlüssel (Algorithmus: „SHA256withRSA“) erstellt.
 * 
 * Der geheime AES-Schlüssel wird mit dem öffentlichen RSA‐Schlüssel
 * (Algorithmus: „RSA“) verschlüsselt.
 * 
 * Anschließend wird eine Dokumentendatei eingelesen und diese Datei wird mit
 * dem symmetrischen AESAlgorithmus (geheimer AES-Schlüssel) im Counter‐Mode
 * („CTR“) verschlüsselt
 * 
 * Abschließend wird eine Ausgabedatei erzeugt und geschrieben.
 * 
 * @author Chris
 *
 */
public class SSF {

	private final static String ALGORITHM_AES = "AES";
	private final static String ALGORITHM_AES_CTR = "AES/CTR/NoPadding";
	private final static String ALGORITHM_RSA = "RSA";
	private final static String ALGORITHM_SIGNATURE = "SHA256withRSA";
	private final static String FILE_EXTENTION = ".ssf";
	private final static int KEY_AES_LENGTH = 128;

	public SSF() {

	}

	/**
	 * Diese Mehtode liest einen privaten RSA‐Schlüssels (.prv) und einen
	 * öffentlichen RSA‐Schlüssels (.pub) aus einer Datei ein.
	 * 
	 * Anschließend wird ein geheimener Schlüssels für den AES‐Algorithmus mit
	 * der Schlüssellänge 128 Bit erzeugt.
	 * 
	 * Des Weiteren wird eine Signatur für den geheimen AES-Schlüssel mit dem
	 * privaten RSA‐Schlüssel (Algorithmus: „SHA256withRSA“) erstellt.
	 * 
	 * Der geheime AES-Schlüssel wird mit dem öffentlichen RSA‐Schlüssel
	 * (Algorithmus: „RSA“) verschlüsselt.
	 * 
	 * Anschließend wird eine Dokumentendatei eingelesen und diese Datei wird
	 * mit dem symmetrischen AESAlgorithmus (geheimer AES-Schlüssel) im
	 * Counter‐Mode („CTR“) verschlüsselt
	 * 
	 * Abschließend wird eine Ausgabedatei erzeugt und geschrieben.
	 * 
	 * @param privateKey
	 *            PrivateKey des jenigen, der die .ssf Datei sendet
	 * @param publicKey
	 *            PublicKey des jenigen, der die .ssf Datei erhalten soll
	 * @param fileIn
	 *            Datei die verschlüsselt werden soll
	 * @param fileOut
	 *            .ssf Dateiname
	 * @throws NoSuchAlgorithmException
	 *             falls Algorithmus nicht gefunden wird
	 * @throws InvalidKeySpecException
	 *             Falls Format nicht gefunden werden kann
	 * @throws IOException
	 *             falls Datei nicht geschrieben oder gelesen werden kann
	 * @throws InvalidKeyException
	 *             Falls Format nicht gefunden werden kann
	 * @throws SignatureException
	 *             falls die Signature nicht erstellt werden kann
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public void sendSecureFile(String privateKey, String publicKey, String fileIn, String fileOut)
			throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException,
			SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {

		KeyRSAReader readerKeyRSA = new KeyRSAReader();
		FileReader readerFile = new FileReader();
		FileWriter writerFile = new FileWriter();

		// a. Einlesen des PublicKey
		PublicKey keyRSAPub = (PublicKey) readerKeyRSA.readRSAKey(publicKey);

		// b. Einlesen des PrivateKeys
		PrivateKey keyRSAPrv = (PrivateKey) readerKeyRSA.readRSAKey(privateKey);

		// c. Erzeugen eines geheimen AES-Schlüssel mit der Schlüssellänge
		// 128Bit
		SecretKey keyAES = this.generateAESKey();

		// d. Erzeugen einer Signatur für den geheimen AES-Schlüssel, welche mit
		// dem PrivateKey erzeugt wird
		byte[] signatureKeyAES = this.generateSignaturForKeyAES(keyAES, keyRSAPrv);

		// e. Verschlüsseln des geheimen AES-Schlüssel mit dem PublicKey
		byte[] encryptedKeyAES = this.encryptKeyAES(keyAES, keyRSAPub);

		// f. Einlesen der Datei und verschlüsseln mit dem geheimen
		// AES-Schlüssel
		byte[] encryptedFile = this.encryptFile(readerFile.readFile(fileIn), keyAES);

		// Erstellung der Ausgabedatei
		byte[] outputFile = this.createOutputFile(encryptedKeyAES, signatureKeyAES, encryptedFile);

		/*
		 * Schreiben der verschlüsselten Datei mit dem Inhalt: 1. AES-Schlüssel
		 * verschlüsselt mit dem PublichKey 2. Signature für den AES-Schlüssel,
		 * erzuegt mit dem PrivateKey 3. Algorithmische Parameter des geheimen
		 * AES-Schlüssels 4. Mit dem AES-Schlüssel verschlüsselte Dateidaten
		 */
		writerFile.writeFile(outputFile, fileOut + FILE_EXTENTION);

	}

	/**
	 * c. Erstellt einen AES-Schlüssel
	 * 
	 * @return AES-Schlüssel
	 * @throws NoSuchAlgorithmException
	 *             Falls AES-Algorithmus nicht gefunden wird
	 */
	private SecretKey generateAESKey() throws NoSuchAlgorithmException {

		KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM_AES);
		generator.init(KEY_AES_LENGTH);
		return generator.generateKey();
	}

	// d.
	/**
	 * Erzeugt eine Signature für einen übergebenen AES-Schlüssel mit einem
	 * übergebenen PrivateKey
	 * 
	 * @param keyAES
	 *            AES-Schlüssel
	 * @param keyRSAPrv
	 *            PrivateKey
	 * @return byte[] mit allen signierten bytes
	 * @throws NoSuchAlgorithmException
	 *             falls Algorithmus nicht gefunden wird
	 * @throws InvalidKeyException
	 *             falls falscher Key der Signatur übergeben wird
	 * @throws SignatureException
	 *             Falls Signatur nicht erstellt werden kann
	 */
	private byte[] generateSignaturForKeyAES(SecretKey keyAES, PrivateKey keyRSAPrv)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature rsaSignature = Signature.getInstance(ALGORITHM_SIGNATURE);
		rsaSignature.initSign(keyRSAPrv);
		rsaSignature.update(keyAES.getEncoded());

		return rsaSignature.sign();

	}

	/**
	 * e. Diese Mehtode Verschlüsselt einen AES-Schlüssel mit einem übergebenen
	 * PublicKey
	 * 
	 * @param keyAES
	 *            AES-Schlüssel
	 * @param keyRSAPub
	 *            PublicKey
	 * @return Mit dem Privatekey verschlüsselter AES-Schlüssel als byte[]
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
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

	/**
	 * Diese Methode erstellt die Ausgabepacket
	 * @param encryptKeyAES Verschlüssselter AES-Schlüssel
	 * @param signatureKeyAES Signatur für den AES-Schlüssel
	 * @param encryptedFile Verschlüsselte Dateidaten
	 * @return Ausgabepacket
	 */
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
		// Sehe CipherEncryption Zeile 112

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
				// TODO
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
