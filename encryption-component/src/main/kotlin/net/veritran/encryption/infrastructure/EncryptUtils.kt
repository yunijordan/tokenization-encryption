package net.veritran.encryption.infrastructure

import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.infrastructure.StringUtils.decode

import java.util.*

import org.jose4j.keys.AesKey

import java.nio.file.Files
import java.nio.file.Paths

import java.security.Key
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import javax.crypto.Cipher
import javax.crypto.Cipher.SECRET_KEY
import javax.crypto.Cipher.UNWRAP_MODE

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

    fun unwrap(
            privateTspKey: Key,
            keyBytes: ByteArray,
            oaepHashingAlgorithm: String,
            wrappedKeyAlgorithm: String = KeyAlgorithms.AES.value
    ): Key {
        val mgf1ParameterSpec = MGF1ParameterSpec(oaepHashingAlgorithm)
        val cipherTransformation =
                "RSA/ECB/OAEPWith{ALG}AndMGF1Padding".replace("{ALG}", mgf1ParameterSpec.digestAlgorithm)
        val oaepParameterSpec = OAEPParameterSpec(
                mgf1ParameterSpec.digestAlgorithm,
                "MGF1",
                mgf1ParameterSpec,
                PSource.PSpecified.DEFAULT
        )
        val cipher = Cipher.getInstance(cipherTransformation)
        cipher.init(UNWRAP_MODE, privateTspKey, oaepParameterSpec)
        return cipher.unwrap(keyBytes, wrappedKeyAlgorithm, SECRET_KEY)
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

    private fun getPrivateKey(key: ByteArray, keyAlgorithm: String): Key {
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

    fun generateIv(ivBytes: ByteArray): IvParameterSpec = IvParameterSpec(ivBytes)

    fun generateAesKey(bytes: ByteArray): Key = AesKey(bytes)

}