package socket;

public class test {
	public static void main(String[] args) throws Exception{
		AES2 aes = new AES2();
		System.out.println(aes.encrypt("HELLO ALL"));
		System.out.println(aes.decrypt("HELLO ALL"));
	}
}