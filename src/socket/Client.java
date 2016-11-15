package socket;

//import java.util.Arrays;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.sql.Array;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {
	public static void main(String[] args) throws ClassNotFoundException {
		try {
			int port_client = 9995;
			
			Socket msocket = new Socket(InetAddress.getLocalHost(), port_client);

			//String password = "1234";
			// write, are used for I/O of primitive types which are int,
			// float,double and so on.
			DataOutputStream dos = new DataOutputStream(msocket.getOutputStream());

			// ------------------KEY EXCHANGE----------------------//
			System.out.println("First step: Public key exchange");
			// get the RSA public key from socket.
			ObjectInputStream ois = new ObjectInputStream(msocket.getInputStream());

			PublicKey serverPublicKey = (PublicKey) ois.readObject();
			System.out.println("Server Public Key is: " + serverPublicKey);

			// Generate the RSA key pair @1
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(512);
			KeyPair clientKey = keyGen.generateKeyPair();
			PublicKey clientPublicKey = clientKey.getPublic();
			PrivateKey clientPrivateKey = clientKey.getPrivate();

			// Write to the output stream and send to server, RSA public key @2
			ObjectOutputStream oos = new ObjectOutputStream(msocket.getOutputStream());
			System.out.println("Client Public Key is: "+ clientPublicKey);
			oos.writeObject(clientPublicKey);
			oos.flush();
			System.out.println("First step finished");
			// ------------------KEY EXCHANGE----------------------//
			
			
			

			// ------------------GENERATE AES KEY----------------------//
			System.out.println("Second step: Generate a AES shared secret key");
			// Generate the AES shared key @1
			KeyGenerator keyGen2 = KeyGenerator.getInstance("AES");
			keyGen2.init(256);
			//keyGen2.init(128, new SecureRandom(password.getBytes())); // for example
			SecretKey secretKey = keyGen2.generateKey();
			SecretKeySpec key = new SecretKeySpec(secretKey.getEncoded(), "AES");
			//byte[] symmetricsKey = secretKey.getEncoded();// Returns copy of the
			System.out.println("the aeskey is" + key);											// key bytes
			System.out.println("AES: " + secretKey);
			System.out.println("Second step finished");
			// ------------------GENERATE AES KEY----------------------//
		
		

			// ---ENCRYPT AES KEY USING THE RECEIVED RSA PUBLIC KEY AND SEND TO SERVER---//
			System.out.println("Third step: Encrypt AES shared secret key");
			String symmetricsKey = key.toString();
			System.out.println("plainkey" + symmetricsKey);
			Cipher cipherR = Cipher.getInstance("RSA");
			cipherR.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			byte[] cipherAESKey = cipherR.doFinal(symmetricsKey.getBytes());
			System.out.println(cipherAESKey);
			dos.writeInt(cipherAESKey.length);
			dos.write(cipherAESKey);
			dos.flush();

			System.out.println("Third step finished");
			// ---ENCRYPT AES KEY USING THE RECEIVED RSA PUBLIC KEY AND SEND TO SERVER---//
			
			
			// ---ENCRYPT MESSAGE USING THE RECEIVED RSA PUBLIC KEY AND SEND TO SERVER---//
			System.out.println("Fourth step: Encrypt message");
			Cipher cipherA = Cipher.getInstance("AES");
			cipherA.init(Cipher.ENCRYPT_MODE, secretKey);
			String plainText = "Type a secret message";
			System.out.println(plainText);
			System.out.println(new String(plainText.getBytes()));
			byte[] cipherText = cipherA.doFinal(plainText.getBytes());
			System.out.println(new String(cipherText));
			dos.writeInt(cipherText.length);
			dos.write(cipherText);
			dos.flush();
			System.out.println("Fourth step finished");
			// ---ENCRYPT MESSAGE USING THE RECEIVED RSA PUBLIC KEY AND SEND TO SERVER---//

			// Write the K[AES] to server
			// byte[] cipherText_AES =
			// cipherAES.doFinal(plainText_AES.getBytes())

			// Write to the output stream and send to server.

			// Cipher cipher = Cipher.getInstance("RSA");
			// cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			// String plainText = "I have a secret";
			// System.out.println(new String(plainText.getBytes()));
			//
			// byte[] cipherText = cipher.doFinal(plainText.getBytes());
			// dos.writeInt(cipherText.length);
			// dos.write(cipherText);
			// dos.flush();

			MessageDigest md = MessageDigest.getInstance("MD5");
			System.out.println("The message digest algorithm used is " + md.getAlgorithm());
			System.out.println("The provider which actually implements this algorithm is " + md.getProvider());
			md.update(plainText.getBytes());
			byte[] messageDigestMD5 = md.digest();
			dos.writeInt(messageDigestMD5.length);
			dos.write(messageDigestMD5);
			dos.flush();

			DataInputStream dis = new DataInputStream(msocket.getInputStream());
			// method reads in a string that has been encoded using a modified
			// UTF-8 format. The string of character is decoded from the UTF and
			// returned as String.
			String result = dis.readUTF();
			System.out.println("The result returned by server is " + result);
			String result2 = dis.readUTF();
			System.out.println("The integrity of message is checked with " + result2);

			dis.close();
			msocket.close();
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException e) {
			e.getStackTrace();
		}
	}

}
