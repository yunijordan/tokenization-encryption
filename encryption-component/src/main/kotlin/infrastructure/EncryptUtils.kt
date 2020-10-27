package infrastructure

import java.security.Key
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.EncodedKeySpec
import java.security.spec.KeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher

object EncryptUtils {

    fun encrypt(message: String, publicKey: String): String {
        val encryptedByte: ByteArray? = cipherMessage(
                "RSA/ECB/PKCS1Padding",
            message.toByteArray(),
            Cipher.ENCRYPT_MODE,
            getPublicKey(publicKey)
        )
        return Base64.getEncoder().encodeToString(encryptedByte)
    }

    fun decrypt(message: String, privateKey: String): String {
        val decryptedByte: ByteArray? = cipherMessage(
                "RSA/ECB/PKCS1Padding",
            Base64.getDecoder().decode(message.toByteArray()),
            Cipher.DECRYPT_MODE,
            getPrivateKey(privateKey)
        )
        return String(decryptedByte!!)
    }

    fun getPublicKey(base64Key: String): Key {
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(base64Key.toByteArray()))
        return getKey(keySpec,keyFactory::generatePublic)
    }

    fun getPrivateKey(base64Key: String): Key {
        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Key.toByteArray()))
        return getKey(keySpec, keyFactory::generatePrivate)
    }

    private fun getKey(keySpec: EncodedKeySpec, generateKey: (keySpec: KeySpec) -> Key): Key {
        return generateKey(keySpec)
    }

    fun signMessage(message: String, privateKey: String): ByteArray? {
        try {
            val hashedMessage = hashMessage(message)
            return cipherMessage("RSA", hashedMessage, Cipher.ENCRYPT_MODE, getPrivateKey(privateKey))
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun verifySign(encryptedMessageHash: ByteArray, message: String, publicKey: String): Boolean {
        try {
            val hashedMessage = hashMessage(message)
            val cipherHashedMessage = cipherMessage("RSA", encryptedMessageHash, Cipher.DECRYPT_MODE, getPublicKey(publicKey))
            return Arrays.equals(hashedMessage, cipherHashedMessage)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    private fun cipherMessage(transformation: String, message: ByteArray, cipherMode: Int, key: Key): ByteArray? {
        val rsa: Cipher
        var encryptedByte: ByteArray? = ByteArray(0)
        try {
            rsa = Cipher.getInstance(transformation)
            rsa.init(cipherMode, key)
            encryptedByte = rsa.doFinal(message)
        } catch (ex: Exception) {
            ex.printStackTrace()
        }
        return encryptedByte
    }

    private fun hashMessage(message: String): ByteArray {
        val messageDigest = MessageDigest.getInstance("SHA-256")
        return messageDigest.digest(message.toByteArray())
    }

}