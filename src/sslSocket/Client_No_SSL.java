package sslSocket;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Color;
import java.awt.Frame;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
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
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import sslSocket.AES;

public class Client_No_SSL {
	
	private TextArea ta;
	private TextField tf;
	private static Socket sock;
	private static DataInputStream dis;
	private static DataOutputStream dos;
	private static ObjectInputStream ois;
	private static ObjectOutputStream oos;
	
	public static void main(String[] args)
	{
		Log frameTable = new Log();
		frameTable.actionlogin();
		while (true) {
			// System.out.println(counter++);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (frameTable.getLoginFlag() == true) {
				break;
			}
		}
		
		Client_No_SSL client = new Client_No_SSL();
		try {
			Socket sock = new Socket(InetAddress.getLocalHost(),8443);
			
			if(sock.isConnected())
			{
				System.out.println("Connected successfully");
			}else
			{
				System.out.println("Connection fails...");
			}
			
			if(sock.isBound())
			{
				System.out.println("Bind successfully");
			}else
			{
				System.out.println("Bind fails...");
			}
			// ------------------KEY EXCHANGE----------------------//
			//System.out.println("First step: Public key exchange");
			// get the RSA public key from socket.
			dos = new DataOutputStream(sock.getOutputStream());
			ois = new ObjectInputStream(sock.getInputStream());
			dis = new DataInputStream(sock.getInputStream());

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
			client.createUI(aeskey);
			client.createThread(aeskey);
			
		} catch (Exception e) {System.out.println(e.getMessage());} 
	}
	
	public void createUI(String aeskey) {
		Frame f = new Frame("Client");
		f.setBackground(new Color(250, 240, 230));
		ta = new TextArea();
		ta.setBackground(new Color(250, 240, 230));
		tf = new TextField();
		Button send = new Button("send");
		send.setForeground(new Color(123, 104, 238));
		Panel p = new Panel();
		p.setLayout(new BorderLayout());
		p.add(tf, "Center");
		p.add(send, "East");
		f.add(ta, "Center");
		f.add(p, "South");
		SendThread sender = new SendThread(sock, this, aeskey);
		send.addActionListener(sender);
		tf.addActionListener(sender);
		f.addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			}
		});
		f.setSize(540, 390);
		f.setLocation(600, 0);
		f.setVisible(true);
	}

	public TextField getTextField() {
		return tf;
	}

	public TextArea getTextArea() {
		return ta;
	}

	public void createThread(String aeskey) {
		RecieveThread receiver = new RecieveThread(sock, this, aeskey);
		receiver.start();
	}

	public void close() {
		try {
			dis.close();
			dos.close();
			sock.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public DataInputStream getDataInputStream() {
		return dis;
	}

	public DataOutputStream getDataOutputStream() {
		return dos;
	}

	public ObjectInputStream getObjectInputStream() {
		return ois;
	}

	public ObjectOutputStream getObjectOutputStream() {
		return oos;
	}
	
}

class SendThread implements ActionListener
{
	private Client_No_SSL client;
	private String aeskey;
	private Socket sock;
	String msgtoServerString;
	TextField tf;
	
	public SendThread(Socket sock, Client_No_SSL client, String aeskey) {
		this.sock = sock;
		this.aeskey = aeskey;
		this.client = client;
	}
	
	public void actionPerformed(ActionEvent e) {
		tf = client.getTextField();
		msgtoServerString = tf.getText();
		client.getTextArea().append("Me: " + msgtoServerString + "\n");
		AES aes = new AES("asilkjdhgbytksgr");
		String encdata = null;
		try {
			encdata = aes.encrypt(msgtoServerString);
		} catch (Exception e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		System.out.println("encrypted data - " + encdata);
		byte[] cip = encdata.getBytes();
		try {
			client.getDataOutputStream().writeInt(cip.length);
			client.getDataOutputStream().write(cip);
			client.getDataOutputStream().flush();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		if (msgtoServerString.equals("EXIT")) {
			client.close();
			System.exit(0);
		}
		tf.setText("");
		tf.requestFocus();
	}
	
}

class RecieveThread extends Thread
{
	private Client_No_SSL client;
	private Socket sock;
	private String aeskey;

	public RecieveThread(Socket sock, Client_No_SSL client, String aeskey) {
		this.sock = sock;
		this.aeskey = aeskey;
		this.client = client;
	}

	public void run() {
		DataInputStream DIS = client.getDataInputStream();
		TextArea ta = client.getTextArea();
		try {
			while (true) {
				int length_message = DIS.readInt();
				byte[] cipherText = null;
				if (length_message > 0) {
					cipherText = new byte[length_message];
					DIS.readFully(cipherText, 0, cipherText.length); 
				}
				System.out.println("The encrypted Message from server is: " + cipherText);
				String messageCipher = new String(cipherText);
				System.out.println("The encrypted string from server is: " + messageCipher);
				AES aes = new AES(aeskey);
				String decdata = aes.decrypt(messageCipher);
				System.out.println("The Message from server is: " + decdata);
				ta.append("Server: " + decdata + "\n");

				if (decdata.equals("Bye")) {
					client.close();
					System.exit(0);
				}
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
}



