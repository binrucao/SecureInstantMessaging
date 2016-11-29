package sslSocket;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class AES {

	private static final String ALGO="AES";
	private byte[] keyValue;
	
	public AES (String key){
		
		keyValue = key.getBytes();
	}
	
	public String encrypt (String Data) throws Exception, NoSuchPaddingException{
		SecretKeySpec key= generateKey();
		Cipher c=Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(Data.getBytes());
		String encryptedValue = new BASE64Encoder().encode(encVal);
		return encryptedValue;
			
	}
	
	public String decrypt(String encryptedData) throws Exception{
		SecretKeySpec key=generateKey();
		Cipher c =Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
		byte[] decValue =c.doFinal(decordedValue);
		String decryptedValue=new String(decValue);
		return decryptedValue;
	}
	SecretKeySpec generateKey(){
		SecretKeySpec key=new SecretKeySpec(keyValue,ALGO);
		return key;
	}
	
		
	}

