package infrastructure;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class EncryptUtils {

    public static String encrypt(String data, String publicKey) {
        Cipher rsa;
        byte[] encryptedByte = new byte[0];
        try {
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
            encryptedByte = rsa.doFinal(data.getBytes());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return Base64.getEncoder().encodeToString(encryptedByte);
    }

    public static String decrypt(String data, String privateKey) {
        Cipher rsa;
        byte[] decryptedByte = new byte[0];
        try {
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
            decryptedByte = rsa.doFinal(Base64.getDecoder().decode(data.getBytes()));
        }catch(Exception ex){
            ex.printStackTrace();
        }
        return new String(decryptedByte);
    }

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e){
            e.printStackTrace();
        }
        return publicKey;
    }


    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] sign(String message, String privateKey) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = md.digest(message.getBytes());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(privateKey));
            return cipher.doFinal(messageHash);

        }catch ( Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verifySign(byte[]  encryptedMessageHash, String message, String publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, getPublicKey(publicKey));
            byte[] decryptedMessageHash = cipher.doFinal(encryptedMessageHash);
            byte[] messageBytes = message.getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] newMessageHash = md.digest(messageBytes);
            return Arrays.equals(decryptedMessageHash, newMessageHash);
        } catch ( Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
