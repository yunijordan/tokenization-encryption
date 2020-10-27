package infrastructure

import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
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

    fun encrypt(message: String, publicKey: String, transformation: String, algorithm: String): String {
        val encryptedByte: ByteArray? = cipherMessage(
                transformation,
            message.toByteArray(),
            Cipher.ENCRYPT_MODE,
            getPublicKey(publicKey, algorithm)
        )
        return Base64.getEncoder().encodeToString(encryptedByte)
    }

    fun decrypt(message: String, privateKey: String, transformation: String, algorithm: String): String {
        val decryptedByte: ByteArray? = cipherMessage(
                transformation,
            Base64.getDecoder().decode(message.toByteArray()),
            Cipher.DECRYPT_MODE,
            getPrivateKey(privateKey, algorithm)
        )
        return String(decryptedByte!!)
    }

    fun getPublicKey(base64Key: String, algorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(algorithm)
        val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(base64Key.toByteArray()))
        return getKey(keySpec,keyFactory::generatePublic)
    }

    fun getPrivateKey(base64Key: String, algorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(algorithm)
        val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Key.toByteArray()))
        return getKey(keySpec, keyFactory::generatePrivate)
    }

    fun signMessage(message: String, privateKey: String, algorithm: String): ByteArray? {
        try {
            val hashedMessage = hashMessage(message)
            return cipherMessage(
                "RSA",
                hashedMessage,
                Cipher.ENCRYPT_MODE,
                getPrivateKey(privateKey, algorithm))
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun verifySign(
        encryptedMessageHash: ByteArray,
        message: String,
        publicKey: String,
        algorithm: String): Boolean {
        try {
            val hashedMessage = hashMessage(message)
            val cipherHashedMessage = cipherMessage(
                "RSA",
                encryptedMessageHash,
                Cipher.DECRYPT_MODE,
                getPublicKey(publicKey, algorithm))
            return Arrays.equals(hashedMessage, cipherHashedMessage)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    private fun getKey(keySpec: EncodedKeySpec, generateKey: (keySpec: KeySpec) -> Key): Key {
        return generateKey(keySpec)
    }

    private fun cipherMessage(
            transformation: String,
            message: ByteArray,
            cipherMode: Int,
            key: Key): ByteArray? {
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