package socket;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PrintStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class MultiCli_En implements Runnable {

	// The client socket
	private static Socket clientSocket = null;
	// The output stream
	private static PrintStream os = null;
	// The input stream
	private static DataInputStream is = null;

	private static BufferedReader inputLine = null;
	private static boolean closed = false;
	static PublicKey serverPublicKey;
	static String aeskey;

	public static void main(String[] args) throws ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		// The default port.
		int portNumber = 2222;
		// The default host.
		String host = "localhost";

		if (args.length < 2) {
			System.out.println("Usage: java MultiThreadChatClient <host> <portNumber>\n" + "Now using host=" + host
					+ ", portNumber=" + portNumber);
		} else {
			host = args[0];
			portNumber = Integer.valueOf(args[1]).intValue();
		}

		/*
		 * Open a socket on a given host and port. Open input and output
		 * streams.
		 */
		try {
			clientSocket = new Socket(host, portNumber);
			inputLine = new BufferedReader(new InputStreamReader(System.in));
			os = new PrintStream(clientSocket.getOutputStream());
			is = new DataInputStream(clientSocket.getInputStream());
			DataOutputStream dos = new DataOutputStream(clientSocket.getOutputStream());
			ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());
			serverPublicKey = (PublicKey) ois.readObject();
			System.out.println("Server Public Key is: " + serverPublicKey);
			
			// ------------------GENERATE AES KEY----------------------//
			AES aes = new AES("asilkjdhgbytksgr");
			SecretKeySpec aeskey1 = aes.generateKey();
			byte[] aeskey2 = aeskey1.getEncoded();
			aeskey = new String(aeskey2);
			
			Cipher cipherkey = Cipher.getInstance("RSA");
			cipherkey.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			byte[] cipheraeskey = cipherkey.doFinal(aeskey.getBytes());
			String cipheraeskey1 = new String(cipheraeskey);
			System.out.println("cipheraeskey is " + cipheraeskey1);
			dos.writeInt(cipheraeskey.length);
			dos.write(cipheraeskey);
			dos.flush();
			
			
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host " + host);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for the connection to the host " + host);
		}

		/*
		 * If everything has been initialized then we want to write some data to
		 * the socket we have opened a connection to on the port portNumber.
		 */
		if (clientSocket != null && os != null && is != null) {
			try {

				/* Create a thread to read from the server. */
				new Thread(new MultiCli_En()).start();
				while (!closed) {
					os.println(inputLine.readLine().trim());
				}
				/*
				 * Close the output stream, close the input stream, close the
				 * socket.
				 */
				os.close();
				is.close();
				clientSocket.close();
			} catch (IOException e) {
				System.err.println("IOException:  " + e);
			}
		}
	}

	/*
	 * Create a thread to read from the server. (non-Javadoc)
	 * 
	 * @see java.lang.Runnable#run()
	 */
	public void run() {
		/*
		 * Keep on reading from the socket till we receive "Bye" from the
		 * server. Once we received that then we want to break.
		 */
		String responseLine;
		try {
			while ((responseLine = is.readLine()) != null) {
//				AES aes = new AES(aeskey);
//				String decdata = aes.decrypt(responseLine);
//				System.out.println(decdata);
				
				System.out.println(responseLine);
				if (responseLine.indexOf("*** Bye") != -1)
					break;
			}
			closed = true;
		} catch (Exception e) {
			System.err.println("IOException:  " + e);
		}
	}
}
