package socket;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import junit.framework.Test;

public class AES2 {
	private String algorithm = "AES";
	private SecretKeySpec keySpec = null;
	private byte[] key = "Wydopqswrlmesf==".getBytes();

	private Cipher cipher = null;

	public AES2() throws NoSuchAlgorithmException, NoSuchPaddingException {
		cipher = Cipher.getInstance(algorithm);
		keySpec = new SecretKeySpec(key, algorithm);
	}

	public String encrypt(String input) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		cipher.init(Cipher.ENCRYPT_MODE, keySpec);

		byte[] inputBytes = input.getBytes();
		System.out.print("EncryptionHelper.encrypt...byte array length: " + inputBytes.length);

		String returnVal = inputBytes.toString();
		System.out.print("EncryptionHelper.encrypt...string interpretation: " + returnVal);

		byte[] finalResult = org.apache.commons.codec.binary.Base64.encodeBase64(cipher.doFinal(inputBytes));

		System.out.println(" Encrypt len = " + finalResult.length + " ");

		String encryptedStr = new String(finalResult);
		System.out.println("EncryptionHelper.encrypt...return value: " + encryptedStr);

		return encryptedStr;

	}

	public String decrypt(String passphrase)
			throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {

		byte[] passPhraseBytes = passphrase.getBytes();
		byte[] encryptionBytes = org.apache.commons.codec.binary.Base64.decodeBase64(passPhraseBytes);
		System.out.print(" String decoded = " + encryptionBytes.toString() + " ");
		System.out.print("Lent=" + encryptionBytes.length + " ");
		cipher.init(Cipher.DECRYPT_MODE, keySpec);
		System.out.print(" testt  ");
		byte[] recoveredBytes = cipher.doFinal(encryptionBytes);
		System.out.print(" testt 2 ");
		String recovered = new String(recoveredBytes);

		System.out.print("EncryptionHelper.decrypt...return value: " + recovered);

		return recovered;
	}
}