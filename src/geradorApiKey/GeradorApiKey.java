package geradorApiKey;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class GeradorApiKey {

	/**
	 *  A Chave que sera utilizada para criptografar e decriptografar
	 *  precisa ter 16 caracteres
	 */
	static String chaveDecrypt = "";
	
	/**
	 * Inserir a chave para ser criptografada Criptografar
	 */
	static String apiKey = "";

	private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

	private static final int GCM_IV_LENGTH = 1;
    private static SecretKeySpec secretKey;

    private GeradorApiKey() {
        throw new IllegalStateException("Utility class");
    }

    public static void setKey(String myKey) {
        try {
            byte[] key = myKey.getBytes(StandardCharsets.UTF_8);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String plaintext, String myKey) {
        try {
            setKey(myKey);
            byte[] iv = new byte[GCM_IV_LENGTH];
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            final Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
            return Base64.getEncoder().encodeToString(byteBuffer.put(iv).put(cipherText).array());
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return null;
    }
    
    public static String descriptografarChave(String message) {
        try {
            setKey(chaveDecrypt);
            byte[] cipherMessage = Base64.getDecoder().decode(message);
            final Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
            AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipherMessage, 0, GCM_IV_LENGTH);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);
            byte[] plainText = cipher.doFinal(cipherMessage, GCM_IV_LENGTH, cipherMessage.length - GCM_IV_LENGTH);
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (Exception e) {
        	 System.out.println("Erro ao descriptografar API-Key inserida");
        }
        return null;
    }

	public static void main(String[] args) {
		
		//INSERIR A CHAVE COM 16 CARACTERES
		String chaveDecrypt = "";
		
		//INSERIR A CHAVE PARA CRIPTOGRAFAR
		String apiKey = "";
		
		String novaSenha = encrypt(apiKey, chaveDecrypt);
		
		System.out.println("APP-KEY Gerada: " + novaSenha);
		
		try {
			String desc = descriptografarChave(novaSenha);
			
			System.out.println("A Chave Descriptografada: " + desc);
		} catch (Exception e) {
			e.printStackTrace();
		}	
		
	}

}
