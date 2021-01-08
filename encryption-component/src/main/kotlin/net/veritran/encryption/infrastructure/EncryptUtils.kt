package net.veritran.encryption.infrastructure

import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.infrastructure.StringUtils.decode
import org.jose4j.keys.AesKey
import java.nio.file.Files
import java.nio.file.Paths
import java.security.Key
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

object EncryptUtils {

    fun encrypt(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        val encryptedBytes = cipherMessage(
            cipherTransformation,
            message.toByteArray(),
            Cipher.ENCRYPT_MODE,
            getPublicKey(publicKey, keyAlgorithm)
        )
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decrypt(
        messageBytes: ByteArray,
        privateKey: Key,
        cipherTransformation: String,
        algorithmParameterSpec: AlgorithmParameterSpec? = null
    ): String {
        val decryptedBytes = cipherMessage(
            cipherTransformation,
            messageBytes,
            Cipher.DECRYPT_MODE,
            privateKey,
            algorithmParameterSpec
        )
        return String(decryptedBytes)
    }

    fun getPublicKey(key: String, keyAlgorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(key.toByteArray()))
        return keyFactory.generatePublic(keySpec)
    }

    fun getPrivateKey(key: String, keyAlgorithm: String): Key = getPrivateKey(decode(key), keyAlgorithm)

    fun getPrivateKey(keyFilePath: String): Key {
        val keyBytes = Files.readAllBytes(Paths.get(keyFilePath))
        return getPrivateKey(keyBytes, KeyAlgorithms.RSA.value)
    }

    fun getPrivateKey(key: ByteArray, keyAlgorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = PKCS8EncodedKeySpec(key)
        return keyFactory.generatePrivate(keySpec)
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

    private fun hashMessage(message: String, algorithm: String): ByteArray {
        val messageDigest = MessageDigest.getInstance(algorithm)
        return messageDigest.digest(message.toByteArray())
    }

    private fun cipherMessage(
        cipherTransformation: String,
        messageBytes: ByteArray,
        cipherMode: Int,
        key: Key,
        algorithmParameterSpec: AlgorithmParameterSpec? = null
    ): ByteArray {
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(cipherMode, key, algorithmParameterSpec)
        return cipher.doFinal(messageBytes)
    }

    fun generateSecretKey(): Key = KeyGenerator.getInstance(KeyAlgorithms.AES.value)
            .also { it.init(128) }
            .generateKey()

    fun generateAesKey(bytes: ByteArray): Key = AesKey(bytes)

}