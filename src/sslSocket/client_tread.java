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
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class client_tread {

	private static String CLIENT_KEY_STORE = "/Users/binrucao/client_ks";   
	private static String CLIENT_KEY_STORE_PASSWORD = "client";
	private TextArea ta;
	private TextField tf;
	private static Socket sock;
	private static DataInputStream dis;
	private static DataOutputStream dos;
    private static ObjectInputStream ois;
    private static ObjectOutputStream oos;

	public static void main(String[] args) throws Exception
	{
		client_tread client = new client_tread();
		client.connect();

			dos = new DataOutputStream(sock.getOutputStream());
			ois = new ObjectInputStream(sock.getInputStream());
			dis = new DataInputStream(sock.getInputStream());

			PublicKey serverPublicKey = (PublicKey) ois.readObject();

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(512);
			KeyPair clientKey = keyGen.generateKeyPair();
			PublicKey clientPublicKey = clientKey.getPublic();
			PrivateKey clientPrivateKey = clientKey.getPrivate();

			ObjectOutputStream oos = new ObjectOutputStream(sock.getOutputStream());

			oos.writeObject(clientPublicKey);
			oos.flush();

			AES aes = new AES("asilkjdhgbytksgr");
			SecretKeySpec aeskey1 = aes.generateKey();
			byte[] aeskey2 = aeskey1.getEncoded();
			String aeskey = new String(aeskey2);

			Cipher cipherkey = Cipher.getInstance("RSA");
			cipherkey.init(Cipher.ENCRYPT_MODE, serverPublicKey);
			byte[] cipheraeskey = cipherkey.doFinal(aeskey.getBytes());
			String cipheraeskey1 = new String(cipheraeskey);

			dos.writeInt(cipheraeskey.length);
			dos.write(cipheraeskey);
			dos.flush();
		
		client.createUI(aeskey);
		System.out.println("Create a new thread");
		client.createThread(aeskey);
		System.out.println("!!!-----------------");

	}

	public void connect() throws Exception{
		try{
			System.setProperty("javax.net.ssl.trustStore", CLIENT_KEY_STORE);   
	        System.setProperty("javax.net.debug", "ssl,handshake"); 
	        sock = clientWithCert();  
		}catch (IOException e) {
            e.printStackTrace();
        }
	}
	public void createUI(String aeskey) {
		Frame f = new Frame("Client");
		ta = new TextArea();
		tf = new TextField();
		Button send = new Button("send");
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
		f.setSize(400, 400);
		f.setLocation(600, 0);
		f.setVisible(true);
	}

	public TextField getTextField() {
		return tf;
	}

	public TextArea getTextArea() {
		return ta;
	} 

	public void createThread(String aeskey){
		RecieveThread receiver = new RecieveThread(sock, this, aeskey);
		receiver.start();
	}
	
	public void close(){
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
    public ObjectInputStream getObjectInputStream(){
    	return ois;
    }
    public ObjectOutputStream getObjectOutputStream(){
    	return oos;
    }
    
	private Socket clientWithoutCert() throws Exception {   
		SocketFactory sf = SSLSocketFactory.getDefault();   
		Socket s = sf.createSocket("localhost", 8443);   
		return s;   
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
}

class SendThread implements ActionListener{
	private client_tread client;
	private String aeskey;
	private Socket sock;
    String msgtoServerString;
    TextField tf;

	public SendThread(Socket sock, client_tread client, String aeskey)
	{
		this.sock = sock;
		this.aeskey = aeskey;
		this.client = client;
	}//end constructor

	public void actionPerformed(ActionEvent e) {
		tf = client.getTextField();
		msgtoServerString = tf.getText();
		client.getTextArea().append("Me: " + msgtoServerString + "\n");
		AES aes = new AES("asilkjdhgbytksgr");
		SecretKeySpec aeskey1 = aes.generateKey();
		byte[] aeskey2 = aeskey1.getEncoded();
		String aeskey = new String(aeskey2);
		String encdata = null;
		try {
			encdata = aes.encrypt(msgtoServerString);
		} catch (Exception e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		System.out.println("encrypted data - " + encdata);
		byte[] cip = encdata.getBytes();
		try{
			client.getDataOutputStream().writeInt(cip.length);
			client.getDataOutputStream().write(cip);
			client.getDataOutputStream().flush();
			}catch(IOException e1){
				e1.printStackTrace();
			}
		if (msgtoServerString.equals("EXIT")){
			client.close();
            System.exit(0);
		}
		tf.setText("");
        tf.requestFocus();
	}// end run method
}// end class

class RecieveThread extends Thread 
{
	private client_tread client;
	private Socket sock;
	private String aeskey;

	public RecieveThread(Socket sock, client_tread client, String aeskey) {
		this.sock = sock;
		this.aeskey = aeskey;
		this.client = client;
	}//end constructor
	public void run() {
		DataInputStream DIS = client.getDataInputStream();
		TextArea ta = client.getTextArea();
		try{
		
			while(true){
				int length_message  = DIS.readInt();
				byte[] cipherText = null;
				if(length_message>0) {
					cipherText = new byte[length_message];
					DIS.readFully(cipherText, 0, cipherText.length); // read the encrypted AES key
				}
				System.out.println("The encrypted Message from server is: " + cipherText);
				String messageCipher = new String(cipherText);
				System.out.println("The encrypted string from server is: " + messageCipher);
				AES aes = new AES(aeskey);
				String decdata = aes.decrypt(messageCipher);
				System.out.println("The Message from server is: " + decdata);
				ta.append("Server(other): " + decdata + "\n");

				if(decdata.equals("EXIT")){
					client.close();
					System.exit(0);
                }
			}
		}catch(Exception e){System.out.println(e.getMessage());}
	}//end run
}//end class recieve thread
