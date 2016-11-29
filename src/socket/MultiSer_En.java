package socket;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PrintStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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

import java.net.ServerSocket;
import java.net.InetAddress;

public class MultiSer_En {

	private static ServerSocket serverSocket = null;
	private static Socket clientSocket = null;
	private static final int maxClientsCount = 10;
	private static final clientThread111[] threads = new clientThread111[maxClientsCount];

	public static void main(String args[]) throws Exception {
		int portNumber = 2222;
		if (args.length < 1) {
			System.out.println(
					"Usage: java MultiThreadChatServerSync <portNumber>\n" + "Now using port number=" + portNumber);
		} else {
			portNumber = Integer.valueOf(args[0]).intValue();
		}

		try {
			serverSocket = new ServerSocket(portNumber);
		} catch (IOException e) {
			System.out.println(e);
		}

		// Generate the RSA key pair 
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair serverKey = keyGen.generateKeyPair();
		PublicKey serverPublicKey = serverKey.getPublic();
		PrivateKey serverPrivateKey = serverKey.getPrivate();

		
		while (true) {
			try {
				clientSocket = serverSocket.accept();
				// send server's public key to client
				ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
				System.out.println("Server Public Key is: " + serverPublicKey);
				oos.writeObject(serverPublicKey);
				oos.flush();
				
				// ------------------Read ENCRYPTED AES KEY FROM CLIENT and DECRYPT IT----------------------//
				
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
				cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
				String aeskey = new String(cipher.doFinal(cipheraeskey));
		        System.out.println("the aeskey is " + aeskey);
		        
		        AES aes = new AES(aeskey);
				
				int i = 0;
				for (i = 0; i < maxClientsCount; i++) {
					if (threads[i] == null) {
						(threads[i] = new clientThread111(clientSocket, threads, aes)).start();
						break;
					}
				}
				if (i == maxClientsCount) {
					PrintStream pos = new PrintStream(clientSocket.getOutputStream());
					pos.println(aes.encrypt("Server too busy. Try later."));
					pos.close();
					clientSocket.close();
				}
			} catch (IOException e) {
				System.out.println(e);
			}
		}
	}
}

class clientThread111 extends Thread {

	private String clientName = null;
	private DataInputStream is = null;
	private BufferedReader br = null;
	private PrintStream pos = null;
	private Socket clientSocket = null;
	private final clientThread111[] threads;
	private int maxClientsCount;
	private DataOutputStream dos = null;
	private ByteArrayOutputStream baos = null;
	AES aes;

	public clientThread111(Socket clientSocket, clientThread111[] threads, AES aes) {
		this.clientSocket = clientSocket;
		this.threads = threads;
		this.aes = aes;
		maxClientsCount = threads.length;
	}
	
	public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
                String hex = Integer.toHexString(buf[i] & 0xFF);
                if (hex.length() == 1) {
                        //hex = ‘0’+hex;
                }
                sb.append(hex.toUpperCase());
        }
        return sb.toString();
	}
	
	public void run() {
		int maxClientsCount = this.maxClientsCount;
		clientThread111[] threads = this.threads;

		try {
			is = new DataInputStream(clientSocket.getInputStream());
			br = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			pos = new PrintStream(clientSocket.getOutputStream());
			String name;
			while (true) {
				pos.println(aes.encrypt("*Enter your name."));
				name = br.readLine().trim();
				if (name.indexOf('@') == -1) {
					break;
				} else {
					pos.println(aes.encrypt("*The name should not contain '@' character."));
				}
			}

			/* Welcome the new the client. */
			pos.println(aes.encrypt("*Welcome "  + " to our chat room.\nTo leave enter /quit in a new line."));
			synchronized (this) {
				for (int i = 0; i < maxClientsCount; i++) {
					if (threads[i] != null && threads[i] == this) {
						clientName = "@" + name;
						break;
					}
				}
				for (int i = 0; i < maxClientsCount; i++) {
					if (threads[i] != null && threads[i] != this) {
						threads[i].pos.println(aes.encrypt("*** A new user " + name + " entered the chat room !!! ***"));
					}
				}
			}
			/* Start the conversation. */
			while (true) {
				String line = br.readLine();
				if (line.startsWith("/quit")) {
					break;
				}
				/* If the message is private sent it to the given client. */
				if (line.startsWith("@")) {
					String[] words = line.split("\\s", 2);
					if (words.length > 1 && words[1] != null) {
						words[1] = words[1].trim();
						if (!words[1].isEmpty()) {
							synchronized (this) {
								for (int i = 0; i < maxClientsCount; i++) {
									if (threads[i] != null && threads[i] != this && threads[i].clientName != null
											&& threads[i].clientName.equals(words[0])) {
										threads[i].pos.println(aes.encrypt("*<" + name + ">* "+ words[1]));
										//Echo this message to let the client know the private message was sent.
										this.pos.println("***" + name + ">>> " + words[1]);
										break;
									}
								}
							}
						}
					}
				} else {
					//The message is public, broadcast it to all other clients.
					synchronized (this) {
						for (int i = 0; i < maxClientsCount; i++) {
							if (threads[i] != null && threads[i].clientName != null) {
								threads[i].pos.println(aes.encrypt("*<" + name + ">* " +line));
							}
						}
					}
				}
			}
			synchronized (this) {
				for (int i = 0; i < maxClientsCount; i++) {
					if (threads[i] != null && threads[i] != this && threads[i].clientName != null) {
						threads[i].pos.println(aes.encrypt("*** The user " + name + " is leaving the chat room !!! ***"));
					}
				}
			}
			pos.println(aes.encrypt("*** Bye " + name + " ***"));
			synchronized (this) {
				for (int i = 0; i < maxClientsCount; i++) {
					if (threads[i] == this) {
						threads[i] = null;
					}
				}
			}
			is.close();
			pos.close();
			br.close();
			dos.close();
			clientSocket.close();
		} catch (Exception e) {
		}
	}
}