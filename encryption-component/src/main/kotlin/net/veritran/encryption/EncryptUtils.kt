package net.veritran.encryption

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
        val decryptedByte: ByteArray? = cipherMessage(
            cipherTransformation,
            Base64.getDecoder().decode(message.toByteArray()),
            Cipher.DECRYPT_MODE,
            getPrivateKey(privateKey, keyAlgorithm)
        )
        return String(decryptedByte!!)
    }

    fun getPublicKey(key: String, keyAlgorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(key.toByteArray()))
        return getKey(keySpec, keyFactory::generatePublic)
    }

    fun getPrivateKey(
        key: String,
        keyAlgorithm: String
    ): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.toByteArray()))
        return getKey(keySpec, keyFactory::generatePrivate)
    }

    fun signMessage(
        message: String,
        privateKey: String,
        algorithm: String,
        transformation: String,
        hashAlgorithm: String
    ): ByteArray? {
        try {
            val hashedMessage = hashMessage(message, hashAlgorithm)
            return cipherMessage(
                transformation,
                hashedMessage,
                Cipher.ENCRYPT_MODE,
                getPrivateKey(privateKey, algorithm)
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    fun verifySign(
        encryptedMessageHash: ByteArray,
        message: String,
        publicKey: String,
        algorithm: String,
        transformation: String,
        hashAlgorithm: String
    ): Boolean {
        try {
            val hashedMessage = hashMessage(message, hashAlgorithm)
            val cipherHashedMessage = cipherMessage(
                transformation,
                encryptedMessageHash,
                Cipher.DECRYPT_MODE,
                getPublicKey(publicKey, algorithm)
            )
            return hashedMessage.contentEquals(cipherHashedMessage)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }

    private fun getKey(keySpec: EncodedKeySpec, generateKey: (keySpec: KeySpec) -> Key): Key {
        return generateKey(keySpec)
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

}