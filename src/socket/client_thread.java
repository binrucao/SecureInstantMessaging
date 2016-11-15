package socket;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class client_thread {
	public static void main(String[] args)
	{
		try {
			Socket sock = new Socket(InetAddress.getLocalHost(),9995);
			
			String password = "1234";
			
			// ------------------KEY EXCHANGE----------------------//
			System.out.println("First step: Public key exchange");
			// get the RSA public key from socket.
			DataOutputStream dos = new DataOutputStream(sock.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());

			PublicKey serverPublicKey = (PublicKey) ois.readObject();
			System.out.println("Server Public Key is: " + serverPublicKey);

			// Generate the RSA key pair @1
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(512);
			KeyPair clientKey = keyGen.generateKeyPair();
			PublicKey clientPublicKey = clientKey.getPublic();
			PrivateKey clientPrivateKey = clientKey.getPrivate();

			// Write to the output stream and send to server, RSA public key @2
			ObjectOutputStream oos = new ObjectOutputStream(sock.getOutputStream());
			System.out.println("Client Public Key is: "+ clientPublicKey);
			oos.writeObject(clientPublicKey);
			oos.flush();
			System.out.println("First step finished");
			// ------------------KEY EXCHANGE----------------------//
			
			// ------------------GENERATE AES KEY----------------------//
			AES aes = new AES("asilkjdhgbytksgr");
			SecretKeySpec aeskey1 = aes.generateKey();
			byte[] aeskey2 = aeskey1.getEncoded();
			String aeskey = new String(aeskey2);
			// ------------------GENERATE AES KEY----------------------//
//			
//			// ---ENCRYPT AES KEY USING THE RECEIVED RSA PUBLIC KEY AND SEND TO SERVER---//
			Cipher cipherkey = Cipher.getInstance("RSA");
			cipherkey.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			byte[] cipheraeskey = cipherkey.doFinal(aeskey.getBytes());
			String cipheraeskey1 = new String(cipheraeskey);
			System.out.println("cipheraeskey is " + cipheraeskey1);
			dos.writeInt(cipheraeskey.length);
			dos.write(cipheraeskey);
			dos.flush();
//			// ---ENCRYPT AES KEY USING THE RECEIVED RSA PUBLIC KEY AND SEND TO SERVER---//
			
			SendThread sendThread = new SendThread(sock, aeskey);
			Thread thread = new Thread(sendThread);thread.start();
			RecieveThread recieveThread = new RecieveThread(sock, aeskey);
			Thread thread2 =new Thread(recieveThread);thread2.start();
		} catch (Exception e) {System.out.println(e.getMessage());} 
	}
}

class SendThread implements Runnable
{
	Socket sock=null;
	PrintWriter print=null;
	BufferedReader brinput=null;
	DataOutputStream dos = null;
	String aeskey;
	
	public SendThread(Socket sock, String aeskey)
	{
		this.sock = sock;
		this.aeskey = aeskey;
	}//end constructor
	public void run(){
		try{
		if(sock.isConnected())
		{
			System.out.println("Client connected to "+sock.getInetAddress() + " on port "+sock.getPort());
			this.print = new PrintWriter(sock.getOutputStream(), true);
			this.dos = new DataOutputStream(sock.getOutputStream());
		while(true){
			System.out.println("Type your message to send to server..type 'EXIT' to exit");
			brinput = new BufferedReader(new InputStreamReader(System.in));
			String msgtoServerString=null;
			msgtoServerString = brinput.readLine();
			AES aes = new AES("asilkjdhgbytksgr");
			SecretKeySpec aeskey1 = aes.generateKey();
			byte[] aeskey2 = aeskey1.getEncoded();
			String aeskey = new String(aeskey2);
			System.out.println("aeskey is " + aeskey);
			String encdata = aes.encrypt(msgtoServerString);
			System.out.println("encrypted data - " + encdata);
			byte[] cip = encdata.getBytes();
			dos.writeInt(cip.length);
			dos.write(cip);
			dos.flush();
		
			if(msgtoServerString.equals("EXIT"))
			break;
			}//end while
		sock.close();}}catch(Exception e){System.out.println(e.getMessage());}
	}//end run method
}//end class

class RecieveThread implements Runnable
{
	Socket sock=null;
	BufferedReader recieve=null;
	DataInputStream reader = null;
	String aeskey;
	public RecieveThread(Socket sock, String aeskey) {
		this.sock = sock;
		this.aeskey = aeskey;
	}//end constructor
	public void run() {
		try{
		recieve = new BufferedReader(new InputStreamReader(this.sock.getInputStream()));//get inputstream
		reader = new DataInputStream(sock.getInputStream());
		while(true){
			int length_message  = reader.readInt();
			byte[] cipherText = null;
			if(length_message>0) {
				cipherText = new byte[length_message];
				reader.readFully(cipherText, 0, cipherText.length); // read the encrypted AES key
			}
			System.out.println("The encrypted Message from server is: " + cipherText);
			String messageCipher = new String(cipherText);
			System.out.println("The encrypted string from servr is: " + messageCipher);
			AES aes = new AES(aeskey);
			String decdata = aes.decrypt(messageCipher);
			System.out.println("The Message from server is: " + decdata);
			System.out.println("Please enter something to send to server..");
		}
		
//		String msgRecieved = null;
//		while((msgRecieved = recieve.readLine())!= null)
//		{
//			System.out.println("From Server: " + msgRecieved);
//			System.out.println("Please enter something to send to server..");
//		}
		}catch(Exception e){System.out.println(e.getMessage());}
	}//end run
}//end class recieve thread
