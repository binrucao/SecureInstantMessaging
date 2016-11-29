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
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
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
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

public class server_tread {
	private static String SERVER_KEY_STORE = "/Users/binrucao/server_ks";   
	private static String SERVER_KEY_STORE_PASSWORD = "server"; 
	private TextArea ta;
	private TextField tf;
	private ServerSocket ss;
	private static Socket clientSocket;
	private static DataInputStream dis;
    private static DataOutputStream dos;
    private static ObjectInputStream ois;
    private static ObjectOutputStream oos;

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
		int port = 8443;

		server_tread gui_s = new server_tread();
		gui_s.connect();

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
		if(length>0) {
			cipheraeskey = new byte[length];
			dis.readFully(cipheraeskey, 0, cipheraeskey.length); // read the cipheraeskey
		}
		String cipheraeskey1=new String(cipheraeskey);

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, serverKey.getPrivate());
		String aeskey = new String(cipher.doFinal(cipheraeskey));
		dos = new DataOutputStream(clientSocket.getOutputStream());
		
		gui_s.createUI(aeskey);
		System.out.println("Create a new thread");
		gui_s.createThread(aeskey);
		System.out.println("Success!!!!--------------");

	}
	public void connect() throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException, InvalidKeyException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException {
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
            // 13701303436

        }
    }
	
	
	public void createUI(String aeskey) {
		Frame f = new Frame("Server");
		ta = new TextArea();
		tf = new TextField();
		Button send = new Button("send");
		Panel p = new Panel();
		p.setLayout(new BorderLayout());
		p.add(tf, "Center");
		p.add(send, "East");
		f.add(ta, "Center");
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
		f.setSize(400, 400);
		f.setVisible(true);
	}

	public TextField getTextField() {
		return tf;
	}

	public TextArea getTextArea() {
		return ta;
	} 


	public void createThread(String aeskey){
		RecieveFromClientThread receiver = new RecieveFromClientThread(clientSocket,aeskey, this);
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
    public ObjectInputStream getObjectInputStream(){
    	return ois;
    }
    public ObjectOutputStream getObjectOutputStream(){
    	return oos;
    }
	
}
class RecieveFromClientThread extends Thread {
	private server_tread gui_s;
	private Socket clientSocket;
	private String aeskey;

	public RecieveFromClientThread(Socket clientSocket, String aeskey, server_tread gui_s)
	{
		this.clientSocket = clientSocket;
		this.aeskey = aeskey;
		this.gui_s = gui_s;
	}

	public void run() {
		DataInputStream DIS =gui_s.getDataInputStream();
        TextArea ta = gui_s.getTextArea();
		try{
			while(true){
				
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
				ta.append("Client(other): " + decdata + "\n");
				if (decdata.equals("bye")) {
                    gui_s.close();
                    System.exit(0);
                }
			}
		}catch(Exception ex){System.out.println(ex.getMessage());}
	}
}//end class RecieveFromClientThread

class SendToClientThread implements ActionListener
{
	private server_tread gui_s;
	private Socket clientSock;
	private String aeskey;
	TextField tf;
	String msgtoClientString;

	public SendToClientThread(Socket clientSock, String aeskey, server_tread gui_s)
	{
		this.clientSock = clientSock;
		this.aeskey=aeskey;
		this.gui_s = gui_s;
	}
	public void actionPerformed(ActionEvent e) {
		tf = gui_s.getTextField();
		msgtoClientString=tf.getText();
		gui_s.getTextArea().append("Me: " + msgtoClientString + "\n");
					AES aes = new AES(aeskey);
					SecretKeySpec aeskey1 = aes.generateKey();
					byte[] aeskey2 = aeskey1.getEncoded();
					String aeskey = new String(aeskey2);
					String encdata = null;
					try{
						encdata = aes.encrypt(msgtoClientString);
					}catch(Exception e1){
						e1.printStackTrace();
						
					}
					System.out.println("encrypted data - " + encdata);
					byte[] cip = encdata.getBytes();
					try {
						gui_s.getDataOutputStream().writeInt(cip.length);
						gui_s.getDataOutputStream().write(cip);
						gui_s.getDataOutputStream().flush();
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
					if(msgtoClientString.equals("EXIT")){
						gui_s.close();
			            System.exit(0);
					}
					tf.setText("");
			        tf.requestFocus();	
	}//end run
}//end class SendToClientThread