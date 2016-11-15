package socket;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class server_thread {
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		int port = 9995;
		System.out.println("Server waiting for connection on port "+port);
		ServerSocket ss = new ServerSocket(port);
		Socket clientSocket = ss.accept();
		System.out.println("Recieved connection from "+clientSocket.getInetAddress()+" on port "+clientSocket.getPort());
		
		// ------------------KEY EXCHANGE----------------------//
		System.out.println("First step: Public key exchange");
		
		// Generate the RSA key pair @1
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair serverKey = keyGen.generateKeyPair();
		PublicKey serverPublicKey = serverKey.getPublic();
		PrivateKey serverPrivateKey = serverKey.getPrivate();
		
		// send server's public key to client
		ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
		System.out.println("Server Public Key is: " + serverPublicKey);
		oos.writeObject(serverPublicKey);
		oos.flush();
		
		// get client's public key
		ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());
		PublicKey clientPublicKey = (PublicKey) ois.readObject();
		System.out.println("Client Public Key is: " + clientPublicKey);
		System.out.println("First step finished");
		// ------------------KEY EXCHANGE----------------------//
		
		
//		// ------------------Read ENCRYPTED AES KEY FROM CLIENT and DECRYPT IT----------------------//
		
		
		DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
		int length = dis.readInt();
		byte[] cipheraeskey = null;
		if(length>0) {
			cipheraeskey = new byte[length];
		    dis.readFully(cipheraeskey, 0, cipheraeskey.length); // read the cipheraeskey
		}
		String cipheraeskey1=new String(cipheraeskey);
		System.out.println("cipheraeskey is " + cipheraeskey1);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String aeskey = new String(cipher.doFinal(cipheraeskey));
        System.out.println("the aeskey is " + aeskey);


//		cipherR.init(Cipher.DECRYPT_MODE, serverPrivateKey);
//		String AESKey = new String(cipherR.doFinal(cipherAESKey));
//		System.out.println("The AES secrect key from client is: " + AESKey);
//		byte[] key = AESKey.getBytes();
//		//System.out.println("AES length is: " + key.length);
//		SecretKey AES = new SecretKeySpec(key, 0 ,key.length, "AES");
//		System.out.println("AES is: " + key.length);
//		
//		// ------------------Read ENCRYPTED AES KEY FROM CLIENT and DECRYPT IT----------------------//
		
		//create two threads to send and receive from client
		RecieveFromClientThread recieve = new RecieveFromClientThread(clientSocket, aeskey);
		Thread thread = new Thread(recieve);
		thread.start();
		SendToClientThread send = new SendToClientThread(clientSocket);
		Thread thread2 = new Thread(send);
		thread2.start();
	}}
class RecieveFromClientThread implements Runnable
{
	Socket clientSocket=null;
	//BufferedReader brBufferedReader = null;
	DataInputStream reader = null;
	//SecretKey AES;
	String aeskey;
	public RecieveFromClientThread(Socket clientSocket, String aeskey /*SecretKey AES*/)
	{
		this.clientSocket = clientSocket;
		this.aeskey = aeskey;
	}//end constructor
	public void run() {
		try{
			while(true){
				//brBufferedReader = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));		
				reader = new DataInputStream(clientSocket.getInputStream());
		        //String messageString;
				int length_message  = reader.readInt();
				byte[] cipherText = null;
				if(length_message>0) {
					cipherText = new byte[length_message];
					reader.readFully(cipherText, 0, cipherText.length); // read the encrypted AES key
				}
				System.out.println("The encrypted Message from client is: " + cipherText);
				String messageCipher = new String(cipherText);
				System.out.println("The encrypted string from client is: " + messageCipher);
				AES aes = new AES(aeskey);
				String decdata = aes.decrypt(messageCipher);
				//System.out.println("decrypted data - " + decdata);
//				Cipher cipherA = Cipher.getInstance("RSA");
//				cipherA.init(Cipher.DECRYPT_MODE, serverPrivateKey);
//				String plainText = new String(cipherA.doFinal(cipherText));
				System.out.println("The Message from client is: " + decdata);	
				System.out.println("Please enter something to send back to client..");	
				
				
//				this.clientSocket.close();
//				System.exit(0);
				}
		}catch(Exception ex){System.out.println(ex.getMessage());}
	}
}//end class RecieveFromClientThread
class SendToClientThread implements Runnable
{
	PrintWriter pwPrintWriter;
	Socket clientSock = null;
	String aeskey;
	public SendToClientThread(Socket clientSock, String aeskey)
	{
		this.clientSock = clientSock;
		this.aeskey = aeskey;
	}
	public void run() {
		try{
		pwPrintWriter =new PrintWriter(new OutputStreamWriter(this.clientSock.getOutputStream()));//get outputstream
		
		while(true)
		{
			String msgToClientString = null;
			BufferedReader input = new BufferedReader(new InputStreamReader(System.in));//get userinput
			
			msgToClientString = input.readLine();//get message to send to client
			
			pwPrintWriter.println(msgToClientString);//send message to client with PrintWriter
			pwPrintWriter.flush();//flush the PrintWriter
			System.out.println("Please enter something to send back to client..");
		}//end while
		}
		catch(Exception ex){System.out.println(ex.getMessage());}	
	}//end run
}//end class SendToClientThread