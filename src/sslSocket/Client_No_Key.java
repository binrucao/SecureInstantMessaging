package sslSocket;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Frame;
import java.awt.Panel;
import java.awt.TextArea;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import java.awt.Color;

public class Client_No_Key {
	public Client_No_Key() {
	}

	private static String CLIENT_KEY_STORE = "/Users/binrucao/client_ks";
	private static String CLIENT_KEY_STORE_PASSWORD = "client";
	private TextArea ta;
	private TextField tf;
	private static Socket sock;
	private static DataInputStream dis;
	private static DataOutputStream dos;
	private static ObjectInputStream ois;
	private static ObjectOutputStream oos;

	public static void main(String[] args) throws Exception {
		Log frameTabel = new Log();
		frameTabel.actionlogin();
		while (true) {
			// System.out.println(counter++);
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (frameTabel.getLoginFlag() == true) {
				break;
			}
		}

		Client_No_Key client = new Client_No_Key();
		client.connect();
		System.out.println("Connection Success!!!!--------------");
		dos = new DataOutputStream(sock.getOutputStream());
		ois = new ObjectInputStream(sock.getInputStream());
		dis = new DataInputStream(sock.getInputStream());

		PublicKey serverPublicKey = (PublicKey) ois.readObject();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair clientKey = keyGen.generateKeyPair();
		PublicKey clientPublicKey = clientKey.getPublic();
		System.out.println("Server Public Key is: " + serverPublicKey);
		ObjectOutputStream oos = new ObjectOutputStream(sock.getOutputStream());
		oos.writeObject(clientPublicKey);
		oos.flush();

		AES aes = new AES("asilkjdhgbytksgr");
		SecretKeySpec aeskey1 = aes.generateKey();
		byte[] aeskey2 = aeskey1.getEncoded();
		String aeskey = new String(aeskey2);
		System.out.println("AES Key is: " + aeskey);
		Cipher cipherkey = Cipher.getInstance("RSA");
		cipherkey.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		byte[] cipheraeskey = cipherkey.doFinal(aeskey.getBytes());
		String cipheraeskey1 = new String(cipheraeskey);

		dos.writeInt(cipheraeskey.length);
		dos.write(cipheraeskey);
		dos.flush();

		client.createUI(aeskey);
		client.createThread(aeskey);

	}

	public void connect() throws Exception {
		try {
			System.setProperty("javax.net.ssl.trustStore", CLIENT_KEY_STORE);
			System.setProperty("javax.net.debug", "ssl,handshake");
			sock = clientWithCert();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static Socket clientWithCert() throws Exception {
		SSLContext context = SSLContext.getInstance("TLS");
		KeyStore ks = KeyStore.getInstance("jceks");

		ks.load(new FileInputStream(CLIENT_KEY_STORE), null);
		KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");
		kf.init(ks, CLIENT_KEY_STORE_PASSWORD.toCharArray());
		context.init(kf.getKeyManagers(), null, null);

		SocketFactory factory = context.getSocketFactory();
		Socket s = factory.createSocket("localhost", 8443);
		return s;
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
		Send_Nokey sender = new Send_Nokey(sock, this);
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
		Recieve_Nokey receiver = new Recieve_Nokey(sock, this);
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

class Send_Nokey implements ActionListener {
	private Client_No_Key client;
	private Socket sock;
	String msgtoServerString;
	TextField tf;

	public Send_Nokey(Socket sock, Client_No_Key client) {
		this.sock = sock;
		this.client = client;
	}// end constructor

	public void actionPerformed(ActionEvent e) {
		tf = client.getTextField();
		msgtoServerString = tf.getText();
		client.getTextArea().append("Me: " + msgtoServerString + "\n");
		AES aes = new AES("wshujdhfgetqokmn");
		String encdata = null;
		try {
			encdata = aes.encrypt(msgtoServerString);
		} catch (Exception e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		System.out.println("encrypted data - " + encdata);
		//byte[] cip = encdata.getBytes();
		byte[] cip = msgtoServerString.getBytes();
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
	}// end run method
}// end class

class Recieve_Nokey extends Thread {
	private Client_No_Key client;
	private Socket sock;

	public Recieve_Nokey(Socket sock, Client_No_Key client) {
		this.sock = sock;
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
				System.out.println("The Message from server is: " + cipherText);
				String messageCipher = new String(cipherText);
				System.out.println("The string from server is: " + messageCipher);
				ta.append("Server: " + messageCipher + "\n");

				if (messageCipher.equals("Bye")) {
					client.close();
					System.exit(0);
				}
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}// end run
}
