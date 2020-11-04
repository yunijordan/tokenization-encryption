package net.veritran.encryption.infrastructure

import net.veritran.encryption.infrastructure.StringUtils.decodeBase64ToBytes
import org.jose4j.keys.AesKey
import java.nio.file.Files
import java.nio.file.Paths
import java.security.Key
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

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
        return getPrivateKey(decodeBase64ToBytes(key), keyAlgorithm)
    }

    fun getPrivateKey(key: ByteArray, keyAlgorithm: String): Key {
        val keyFactory = KeyFactory.getInstance(keyAlgorithm)
        val keySpec = PKCS8EncodedKeySpec(key)
        return keyFactory.generatePrivate(keySpec)
    }

    fun getPrivateKey(keyFilePath: String): Key {
        return getPrivateKey(Files.readAllBytes(Paths.get(keyFilePath)), "RSA")
    }

    fun getUnwrappedKey(privateTspKey: Key, encryptedAesKey: String, oaepHashingAlgorithm: String): Key {
        val encryptedAesKeyBytes = StringUtils.decodeHexToBytes(encryptedAesKey)
        return unwrapKey(privateTspKey, encryptedAesKeyBytes, oaepHashingAlgorithm)
    }

    fun decryptData(unwrappedKey: Key, initialVector: String, encryptedDataBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = generateIv(initialVector)
        cipher.init(2, unwrappedKey, iv)
        return cipher.doFinal(encryptedDataBytes)
    }

    private fun generateIv(iv: String): IvParameterSpec? {
        try {
            val ivByteArray = StringUtils.decodeHexToBytes(iv)
            return IvParameterSpec(ivByteArray)
        } catch (ex: Exception) {
            throw RuntimeException()
        }
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

    private fun unwrapKey(privateTspKey: Key, encryptedAesKeyBytes: ByteArray, oaepHashingAlgorithm: String): Key {
        return try {
            val mgf1ParameterSpec = MGF1ParameterSpec(oaepHashingAlgorithm)
            val asymmetricCipher =
                "RSA/ECB/OAEPWith{ALG}AndMGF1Padding".replace("{ALG}", mgf1ParameterSpec.digestAlgorithm)
            val cipher = Cipher.getInstance(asymmetricCipher)
            cipher.init(4, privateTspKey, getOaepParameterSpec(mgf1ParameterSpec))
            cipher.unwrap(encryptedAesKeyBytes, "AES", 3)
        } catch (ex: Exception) {
            throw RuntimeException()
        }
    }

    private fun getOaepParameterSpec(mgf1ParameterSpec: MGF1ParameterSpec): OAEPParameterSpec? {
        return OAEPParameterSpec(
            mgf1ParameterSpec.digestAlgorithm,
            "MGF1",
            mgf1ParameterSpec,
            PSource.PSpecified.DEFAULT
        )
    }

}