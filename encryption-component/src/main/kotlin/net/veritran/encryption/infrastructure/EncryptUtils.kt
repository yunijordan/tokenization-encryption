package net.veritran.encryption.infrastructure

import org.jose4j.keys.AesKey
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher

object EncryptUtils {

    fun encrypt(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        val encryptedByte = cipherMessage(
            cipherTransformation,
            message.toByteArray(),
            Cipher.ENCRYPT_MODE,
            getPublicKey(publicKey, keyAlgorithm)
        )
        return Base64.getEncoder().encodeToString(encryptedByte)
    }

    fun decrypt(
        message: String,
        privateKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        val decryptedByte = cipherMessage(
            cipherTransformation,
            Base64.getDecoder().decode(message.toByteArray()),
            Cipher.DECRYPT_MODE,
            getPrivateKey(privateKey, keyAlgorithm)
        )
        return String(decryptedByte)
    }

    fun getPublicKey(key: String, keyAlgorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(key.toByteArray()))
        return keyFactory.generatePublic(keySpec)
    }

    fun getPrivateKey(key: String, keyAlgorithm: String): Key {
       return getPrivateKey(convertToByteArryBase64(key), keyAlgorithm)
    }

    fun getPrivateKey(key: ByteArray, keyAlgorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = PKCS8EncodedKeySpec(key)
        return keyFactory.generatePrivate(keySpec)
    }

    fun getPrivateKey(keyFilePath: String): Key {
        return getPrivateKey(Files.readAllBytes(Paths.get(keyFilePath)),"RSA")
    }

    fun generateAesKey(bytes: ByteArray): Key {
        return AesKey(bytes)
    }

    fun signMessage(
        message: String,
        privateKey: String,
        keyAlgorithm: String,
        cipherTransformation: String,
        hashAlgorithm: String
    ): ByteArray {
        val hashedMessage = hashMessage(message, hashAlgorithm)
        return cipherMessage(
            cipherTransformation,
            hashedMessage,
            Cipher.ENCRYPT_MODE,
            getPrivateKey(privateKey, keyAlgorithm)
        )
    }

    fun verifySign(
        encryptedMessageHash: ByteArray,
        message: String,
        publicKey: String,
        keyAlgorithm: String,
        transformation: String,
        hashAlgorithm: String
    ): Boolean {
        val cipherHashedMessage = cipherMessage(
            transformation,
            encryptedMessageHash,
            Cipher.DECRYPT_MODE,
            getPublicKey(publicKey, keyAlgorithm)
        )
        val hashedMessage = hashMessage(message, hashAlgorithm)
        return hashedMessage.contentEquals(cipherHashedMessage)
    }

    private fun cipherMessage(
        cipherTransformation: String,
        message: ByteArray,
        cipherMode: Int,
        key: Key
    ): ByteArray {
        val rsa = Cipher.getInstance(cipherTransformation)
        rsa.init(cipherMode, key)
        return rsa.doFinal(message)
    }

    private fun hashMessage(message: String, algorithm: String): ByteArray {
        val messageDigest = MessageDigest.getInstance(algorithm)
        return messageDigest.digest(message.toByteArray())
    }

    private  fun convertToByteArryBase64(key:String):ByteArray {
        return Base64.getDecoder().decode(key.toByteArray())
    }
}