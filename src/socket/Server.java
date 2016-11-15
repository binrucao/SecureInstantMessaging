package socket;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		int port_server = 9995;
		ServerSocket mss = new ServerSocket(port_server);
		
		try {
			while(true) {
				Socket ms = mss.accept();
				
				try {
					// ------------------KEY EXCHANGE----------------------//
					System.out.println("First step: Public key exchange");
					
					// Generate the RSA key pair @1
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
					keyGen.initialize(512);
					KeyPair serverKey = keyGen.generateKeyPair();
					PublicKey serverPublicKey = serverKey.getPublic();
					PrivateKey serverPrivateKey = serverKey.getPrivate();
					
					// send server's public key to client
					ObjectOutputStream oos = new ObjectOutputStream(ms.getOutputStream());
					System.out.println("Server Public Key is: " + serverPublicKey);
					oos.writeObject(serverPublicKey);
					oos.flush();
					
					// get client's public key
					ObjectInputStream ois = new ObjectInputStream(ms.getInputStream());
					PublicKey clientPublicKey = (PublicKey) ois.readObject();
					System.out.println("Client Public Key is: " + clientPublicKey);
					System.out.println("First step finished");
					// ------------------KEY EXCHANGE----------------------//
					
					
					
					
					// ------------------Read ENCRYPTED AES KEY FROM CLIENT and DECRYPT IT----------------------//
					DataInputStream dis = new DataInputStream(ms.getInputStream());
					int length = dis.readInt();
					byte[] cipherAESKey = null;
					if(length>0) {
						cipherAESKey = new byte[length];
					    dis.readFully(cipherAESKey, 0, cipherAESKey.length); // read the encrypted AES key
					}
					//dis.close();
					System.out.println("The encrypted AES secrect key from client is: " + cipherAESKey);
					Cipher cipherR = Cipher.getInstance("RSA");
					cipherR.init(Cipher.DECRYPT_MODE, serverPrivateKey);
					String AESKey = new String(cipherR.doFinal(cipherAESKey));
					System.out.println("The AES secrect key from client is: " + AESKey);
					byte[] key = AESKey.getBytes();
					SecretKey AES = new SecretKeySpec(key, 0 ,key.length, "AES");
					
					// ------------------Read ENCRYPTED AES KEY FROM CLIENT and DECRYPT IT----------------------//
					
					
					// ------------------Read ENCRYPTED message FROM CLIENT and DECRYPT IT----------------------//
					//DataInputStream dis = new DataInputStream(ms.getInputStream());
					int length_message = dis.readInt();
					byte[] cipherText = null;
					if(length_message>0) {
						cipherText = new byte[length_message];
					    dis.readFully(cipherText, 0, cipherText.length); // read the encrypted AES key
					}
					System.out.println("The encrypted Message from client is: " + cipherText);
					Cipher cipherA = Cipher.getInstance("AES");
					cipherA.init(Cipher.DECRYPT_MODE, AES);
					String plainText = new String(cipherA.doFinal(cipherText));
					System.out.println("The Message from client is: " + plainText);
					String result = "The encrypted AES secrect key from server is: " + plainText;
					
					
					
					
//					byte[] cipherText_AES = null;
//					if(length>0) {
//						cipherText_AES = new byte[length];
//					    dis.readFully(cipherText_AES, 0, cipherText_AES.length); // read the message
//					}
//					
//					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//					cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
//					String plainText_AES = new String(cipher.doFinal(cipherText_AES));
//					String result = "The encrypted AES secrect key from server is: " + plainText_AES;
					
					MessageDigest md = MessageDigest.getInstance("MD5");
					int lengthMd = dis.readInt();
					
					byte[] receivedMd = null;
					if(lengthMd>0) {
						receivedMd = new byte[lengthMd];
					    dis.readFully(receivedMd, 0, receivedMd.length); // read the message
					}
					md.update(plainText.getBytes());
					byte[] messageDigestMD5 = md.digest();
			
					DataOutputStream dos = new DataOutputStream(ms.getOutputStream());
					dos.writeUTF(result);
					if(Arrays.equals(messageDigestMD5, receivedMd)) {
						dos.writeUTF("yes");
					}else{
						dos.writeUTF("no");
					}
					
					dos.flush();
					dos.close();
					oos.close();
				} finally {
					ms.close();
				}
			}
		} finally {
			mss.close();
		}
	}	
}

