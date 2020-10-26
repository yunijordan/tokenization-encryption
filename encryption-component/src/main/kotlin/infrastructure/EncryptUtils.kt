package infrastructure

import javax.crypto.Cipher
import java.lang.Exception
import java.security.*
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

object EncryptUtils {

    fun encrypt(message: String, publicKey: String): String {
        val encryptedByte: ByteArray? = cipherMessage(
            message.toByteArray(),
            Cipher.ENCRYPT_MODE,
            getPublicKey(publicKey))
        return Base64.getEncoder().encodeToString(encryptedByte)
    }

    fun decrypt(message: String, privateKey: String): String {
        val decryptedByte: ByteArray? = cipherMessage(
            Base64.getDecoder().decode(message.toByteArray()),
            Cipher.DECRYPT_MODE,
            getPrivateKey(privateKey))
        return String(decryptedByte!!)
    }

    private fun cipherMessage(message: ByteArray, cipherMode: Int, key: Key): ByteArray? {
        val rsa: Cipher
        var encryptedByte: ByteArray? = ByteArray(0)
        try {
            rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            rsa.init(cipherMode, key)
            encryptedByte = rsa.doFinal(message)
        } catch (ex: Exception) {
            ex.printStackTrace()
        }
        return encryptedByte
    }

    fun getPublicKey(base64PublicKey: String): PublicKey {
        lateinit var publicKey: PublicKey
        try {
            val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.toByteArray()))
            val keyFactory = KeyFactory.getInstance("RSA")
            publicKey = keyFactory.generatePublic(keySpec)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
        return publicKey
    }

    fun getPrivateKey(base64PrivateKey: String): PrivateKey {
        lateinit var privateKey: PrivateKey
        try {
            val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.toByteArray()))
            val keyFactory = KeyFactory.getInstance("RSA")
            privateKey = keyFactory.generatePrivate(keySpec)
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
        return privateKey
    }

    fun signMessage(message: String, privateKey: String): ByteArray? {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val messageHash = md.digest(message.toByteArray())
            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(privateKey))
            return cipher.doFinal(messageHash)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun verifySign(encryptedMessageHash: ByteArray, message: String, publicKey: String): Boolean {
        try {
            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.DECRYPT_MODE, getPublicKey(publicKey))
            val decryptedMessageHash = cipher.doFinal(encryptedMessageHash)
            val messageBytes = message.toByteArray()
            val md = MessageDigest.getInstance("SHA-256")
            val newMessageHash = md.digest(messageBytes)
            return Arrays.equals(decryptedMessageHash, newMessageHash)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

}