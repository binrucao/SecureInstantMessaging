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

import javax.swing.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.awt.Color;
import java.awt.ComponentOrientation;

public class server_tread {
	private static String SERVER_KEY_STORE = "/Users/binrucao/server_ks";
	private static String SERVER_KEY_STORE_PASSWORD = "server";
	private TextArea ta;
	private JTextPane textPane;
	private TextField tf;
	private ServerSocket ss;
	private static Socket clientSocket;
	private static DataInputStream dis;
	private static DataOutputStream dos;
	private static ObjectInputStream ois;
	private static ObjectOutputStream oos;

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException,
			NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
			KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {

		Log2 frameTabel = new Log2();
		frameTabel.actionlogin();
//		if(frameTabel.authenticate() == true){
			
		int port = 8443;
		server_tread server = new server_tread();
		server.connect();

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair serverKey = keyGen.generateKeyPair();
		PublicKey serverPublicKey = serverKey.getPublic();
		PrivateKey serverPrivateKey = serverKey.getPrivate();

		// send server's public key to client
		oos = new ObjectOutputStream(clientSocket.getOutputStream());
		System.out.println("Server Public Key is: " + serverPublicKey);
		oos.writeObject(serverPublicKey);
		oos.flush();

		// get client's public key
		ois = new ObjectInputStream(clientSocket.getInputStream());
		PublicKey clientPublicKey = (PublicKey) ois.readObject();
		System.out.println("Received Public Key is: " + clientPublicKey);
		dis = new DataInputStream(clientSocket.getInputStream());
		int length = dis.readInt();
		byte[] cipheraeskey = null;
		if (length > 0) {
			cipheraeskey = new byte[length];
			dis.readFully(cipheraeskey, 0, cipheraeskey.length); // read the
																	// cipheraeskey
		}
		// String cipheraeskey1=new String(cipheraeskey);

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String aeskey = new String(cipher.doFinal(cipheraeskey));
		dos = new DataOutputStream(clientSocket.getOutputStream());

		server.createUI(aeskey);
		System.out.println("Create a new thread");
		server.createThread(aeskey);
		System.out.println("Success!!!!--------------");
		//}

	}

	public void connect() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException,
			CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeyException,
			ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {
		try {

			int port = 8443;
			System.setProperty("javax.net.ssl.trustStore", SERVER_KEY_STORE);
			SSLContext context = SSLContext.getInstance("TLS");

			KeyStore ks = KeyStore.getInstance("jceks");
			ks.load(new FileInputStream(SERVER_KEY_STORE), null);
			KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");
			kf.init(ks, SERVER_KEY_STORE_PASSWORD.toCharArray());

			context.init(kf.getKeyManagers(), null, null);

			ServerSocketFactory factory = context.getServerSocketFactory();
			ss = factory.createServerSocket(port);
			((SSLServerSocket) ss).setNeedClientAuth(true);
			clientSocket = ss.accept();

		} catch (IOException e) {
			e.printStackTrace();

		}
	}

	public void createUI(String aeskey) {
		Frame f = new Frame("Server");
		f.setBackground(new Color(250, 240, 230));
		textPane = new JTextPane();
		textPane.setForeground(new Color(0, 0, 0));
		textPane.setBackground(new Color(250, 240, 230));
//		ta = new TextArea();
//		ta.setBackground(new Color(250, 240, 230));
		tf = new TextField();
		Button send = new Button("send");
		send.setForeground(new Color(123, 104, 238));
		Panel p = new Panel();
		p.setBackground(new Color(173, 216, 230));
		p.setLayout(new BorderLayout());
		p.add(tf, "Center");
		p.add(send, "East");
//		f.add(ta, "Center");
		f.add(textPane, "Center");
		f.add(p, "South");
		AES aes;
		SendToClientThread sender = new SendToClientThread(clientSocket, aeskey, this);
		send.addActionListener(sender);
		tf.addActionListener(sender);
		f.addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			}
		});
		f.setSize(540, 390);
		f.setVisible(true);
	}

	public TextField getTextField() {
		return tf;
	}

//	public TextArea getTextArea() {
//		return ta;
//	}
	
	public JTextPane getTextPane() {
		return textPane;
	}

	public void createThread(String aeskey) {
		RecieveFromClientThread receiver = new RecieveFromClientThread(clientSocket, aeskey, this);
		receiver.start();
	}

	public void close() {
		try {
			dis.close();
			dos.close();
			clientSocket.close();
			ss.close();
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

class RecieveFromClientThread extends Thread {
	private server_tread server;
	private Socket clientSocket;
	private String aeskey;

	public RecieveFromClientThread(Socket clientSocket, String aeskey, server_tread server) {
		this.clientSocket = clientSocket;
		this.aeskey = aeskey;
		this.server = server;
	}

	public void run() {
		DataInputStream DIS = server.getDataInputStream();
//		TextArea ta = server.getTextArea();
		JTextPane textPane = server.getTextPane();
		try {
			while (true) {

				int length_message = DIS.readInt();

				byte[] cipherText = null;
				if (length_message > 0) {
					cipherText = new byte[length_message];
					DIS.readFully(cipherText, 0, cipherText.length);
				}

				System.out.println("The encrypted Message from client is: " + cipherText);
				String messageCipher = new String(cipherText);
				System.out.println("The encrypted string from client is: " + messageCipher);
				AES aes = new AES(aeskey);
				String decdata = aes.decrypt(messageCipher);
				System.out.println("The Message from client is: " + decdata);
				System.out.println("Please enter something to send back to client..");
//				ta.append("Client: " + decdata + "\n");
				//editorPane.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
				textPane.setText(textPane.getText() + "Client: " + decdata + "\n");
				if (decdata.equals("bye")) {
					server.close();
					System.exit(0);
				}
			}
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
		}
	}
}// end class RecieveFromClientThread

class SendToClientThread implements ActionListener {
	private server_tread server;
	private Socket clientSock;
	private String aeskey;
	TextField tf;
	String msgtoClientString;

	public SendToClientThread(Socket clientSock, String aeskey, server_tread server) {
		this.clientSock = clientSock;
		this.aeskey = aeskey;
		this.server = server;
	}

	public void actionPerformed(ActionEvent e) {
		tf = server.getTextField();
		msgtoClientString = tf.getText();
//		server.getTextArea().setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
//		server.getTextArea().append("Me: " + msgtoClientString + "\n");
		
		//server.getTextPane().setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
		server.getTextPane().setText(server.getTextPane().getText() + "Me: " + msgtoClientString + "\n");
		
		
		AES aes = new AES(aeskey);
		SecretKeySpec aeskey1 = aes.generateKey();
		byte[] aeskey2 = aeskey1.getEncoded();
		String aeskey = new String(aeskey2);
		String encdata = null;
		try {
			encdata = aes.encrypt(msgtoClientString);
		} catch (Exception e1) {
			e1.printStackTrace();

		}
		System.out.println("encrypted data - " + encdata);
		byte[] cip = encdata.getBytes();
		try {
			server.getDataOutputStream().writeInt(cip.length);
			server.getDataOutputStream().write(cip);
			server.getDataOutputStream().flush();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		if (msgtoClientString.equals("EXIT")) {
			server.close();
			System.exit(0);
		}
		tf.setText("");
		tf.requestFocus();
	}// end run
}// end class SendToClientThread

class Log2 extends JFrame {

	JButton blogin = new JButton("Login");
	JPanel panel = new JPanel();
	JTextField txuser = new JTextField(15);
	JPasswordField pass = new JPasswordField(15);

	Log2() {
		super("Login Autentification");
		setSize(300, 200);
		setLocation(500, 280);
		panel.setLayout(null);

		txuser.setBounds(70, 30, 150, 20);
		pass.setBounds(70, 65, 150, 20);
		blogin.setBounds(110, 100, 80, 20);

		panel.add(blogin);
		panel.add(txuser);
		panel.add(pass);

		getContentPane().add(panel);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setVisible(true);
		actionlogin();
	}

	public void actionlogin() {
		blogin.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent ae) {
				String puname = txuser.getText();
				String ppaswd = pass.getText();
				if (puname.equals("test") && ppaswd.equals("12345")) {
//					// newframe regFace = new newframe();
//					client_tread regFace = new client_tread();
//					regFace.setVisible(true);
					dispose();
				} else {

					JOptionPane.showMessageDialog(null, "Wrong Password / Username");
					txuser.setText("");
					pass.setText("");
					txuser.requestFocus();
				}

			}
		});
	}
	
	public boolean authenticate(){
		String puname = txuser.getText();
		String ppaswd = pass.getText();
		if (puname.equals("test") && ppaswd.equals("12345")) {
            return true;
        }
		else if(puname == null || ppaswd == null){
			return false;
		}
        return false;
	}
}
