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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import javax.crypto.spec.SecretKeySpec;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

public class GUI_server {
    private static String SERVER_KEY_STORE = "/Users/binrucao/server_ks";   
    private static String SERVER_KEY_STORE_PASSWORD = "server"; 
    private TextArea ta;
    private TextField tf;
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
		int port = 8443;
		GUI_server gui_s = new GUI_server();
		gui_s.createUI();
		
		System.setProperty("javax.net.ssl.trustStore", SERVER_KEY_STORE);   
        SSLContext context = SSLContext.getInstance("TLS");   
           
        KeyStore ks = KeyStore.getInstance("jceks");   
        ks.load(new FileInputStream(SERVER_KEY_STORE), null);   
        KeyManagerFactory kf = KeyManagerFactory.getInstance("SunX509");   
        kf.init(ks, SERVER_KEY_STORE_PASSWORD.toCharArray());   
        context.init(kf.getKeyManagers(), null, null);   
  
        ServerSocketFactory factory = context.getServerSocketFactory();   
        ServerSocket ss = factory.createServerSocket(port);   
        ((SSLServerSocket) ss).setNeedClientAuth(true); 
		Socket clientSocket = ss.accept();

		// ------------------KEY EXCHANGE----------------------//
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair serverKey = keyGen.generateKeyPair();
		PublicKey serverPublicKey = serverKey.getPublic();
		PrivateKey serverPrivateKey = serverKey.getPrivate();
		
		ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
		oos.writeObject(serverPublicKey);
		oos.flush();
		
		ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream());
		PublicKey clientPublicKey = (PublicKey) ois.readObject();

		// ------------------Read ENCRYPTED AES KEY FROM CLIENT and DECRYPT IT----------------------//
		DataInputStream dis = new DataInputStream(clientSocket.getInputStream());
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
		
		gui_s.createThread();
		
    }

    public void createUI() {
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
        SendToClientThread2 sender = new SendToClientThread2(this);
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
	
	public void createThread(){
		RecieveFromClientThread2 receiver = new RecieveFromClientThread2(this);
		receiver.start();
	}

}

class RecieveFromClientThread2 extends Thread 
{
	private GUI_server server;
	Socket clientSocket=null;
	DataInputStream reader = null;
	String aeskey;
	
	public RecieveFromClientThread2(GUI_server server){
		this.server = server;
	}
	
	public RecieveFromClientThread2(Socket clientSocket, String aeskey, GUI_server server)
	{
		this.clientSocket = clientSocket;
		this.aeskey = aeskey;
		this.server = server;
	}
	
	public void run() {
		try{
			while(true){
				TextArea ta = server.getTextArea();
				//brBufferedReader = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));		
				reader = new DataInputStream(clientSocket.getInputStream());
				int length_message  = reader.readInt();
				byte[] cipherText = null;
				if(length_message>0) {
					cipherText = new byte[length_message];
					reader.readFully(cipherText, 0, cipherText.length); // read the encrypted AES key
				}
				String messageCipher = new String(cipherText);
				System.out.println("The encrypted string from client is: " + messageCipher);
				AES aes = new AES(aeskey);
				String decdata = aes.decrypt(messageCipher);
				ta.append("Client(other): " + decdata + "\n");
				//System.out.println("The Message from client is: " + decdata);	
				//System.out.println("Please enter something to send back to client..");	
				
				
//				this.clientSocket.close();
//				System.exit(0);
				}
		}catch(Exception ex){System.out.println(ex.getMessage());}
	}
}//end class RecieveFromClientThread

class SendToClientThread2 implements ActionListener
{
	private GUI_server server;
	PrintWriter pwPrintWriter;
	Socket clientSock = null;
	BufferedReader brinput=null;
	DataOutputStream dos = null;
	String aeskey;
	
	public SendToClientThread2(GUI_server server){
		this.server = server;
	}

	public SendToClientThread2(Socket clientSock, String aeskey)
	{
		this.clientSock = clientSock;
		this.aeskey=aeskey;
	}
	public void actionPerformed(ActionEvent e) {
		try{
			if(clientSock.isConnected())
			{

				TextField tf = server.getTextField();
//				this.pwPrintWriter = new PrintWriter(clientSock.getOutputStream(), true);
//				this.dos = new DataOutputStream(clientSock.getOutputStream());
			    while(true){
//				System.out.println("Type your message to send to client..type 'EXIT' to exit");
//				brinput = new BufferedReader(new InputStreamReader(System.in));
//				String msgtoClientString=null;
//				msgtoClientString = brinput.readLine();
				String msgtoClientString=tf.getText();
				server.getTextArea().append("Me: " + msgtoClientString + "\n");
				AES aes = new AES(aeskey);
				SecretKeySpec aeskey1 = aes.generateKey();
				byte[] aeskey2 = aeskey1.getEncoded();
				String aeskey = new String(aeskey2);
				String encdata = aes.encrypt(msgtoClientString);
				System.out.println("encrypted data - " + encdata);
				byte[] cip = encdata.getBytes();
				dos.writeInt(cip.length);
				dos.write(cip);
				dos.flush();
				if(msgtoClientString.equals("EXIT"))
				break;
				}
			    clientSock.close();}}catch(Exception ex){System.out.println(ex.getMessage());}	
	}//end run
}//end class SendToClientThread