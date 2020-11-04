package net.veritran.encryption.action

import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource.PSpecified

class DecryptMdesMessage {

    fun execute(encryptedData: String, encryptedAesKey: String, oaepHashingAlgorithm: String, initialVector: String, privateKey: Key): String {
        val encryptedDataBytes = decodeEncryptedData(encryptedData)
        val secretKey = getSecretKey(privateKey, encryptedAesKey, oaepHashingAlgorithm)
        val decryptedBytes = decryptData(secretKey, initialVector, encryptedDataBytes)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    private fun decryptData(secretKey: Key, initialVector: String, encryptedDataBytes: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = generateIv(initialVector)
        cipher.init(2, secretKey, iv)
        return cipher.doFinal(encryptedDataBytes)
    }

    private fun getSecretKey(privateKey: Key, encryptedAesKey: String, oaepHashingAlgorithm: String): Key {
        val encryptedAesKeyBytes = decodeValue(encryptedAesKey)
        return unwrapKey(privateKey, encryptedAesKeyBytes, oaepHashingAlgorithm)
    }

    private fun unwrapKey(privateKey: Key, encryptedAesKeyBytes: ByteArray, oaepHashingAlgorithm: String): Key {
        return try {
            val mgf1ParameterSpec = MGF1ParameterSpec(oaepHashingAlgorithm)
            val key: Key = privateKey
            val asymmetricCipher = "RSA/ECB/OAEPWith{ALG}AndMGF1Padding".replace("{ALG}", mgf1ParameterSpec.digestAlgorithm)
            val cipher = Cipher.getInstance(asymmetricCipher)
            cipher.init(4, key, getOaepParameterSpec(mgf1ParameterSpec))
            cipher.unwrap(encryptedAesKeyBytes, "AES", 3)
        } catch (ex: Exception) {
            throw RuntimeException()
        }
    }

    private fun generateIv(iv: String): IvParameterSpec? {
        try {
            val ivByteArray = decodeValue(iv)
            return IvParameterSpec(ivByteArray)
        } catch (ex: Exception) {
            throw RuntimeException()
        }
    }

    private fun getOaepParameterSpec(mgf1ParameterSpec: MGF1ParameterSpec): OAEPParameterSpec? {
        return OAEPParameterSpec(mgf1ParameterSpec.digestAlgorithm, "MGF1", mgf1ParameterSpec, PSpecified.DEFAULT)
    }

    private fun decodeEncryptedData(encryptedData: String) : ByteArray {
        return decodeValue(encryptedData)
    }

    private fun decodeValue(value: String): ByteArray {
            val length = value.length
            val bytes = ByteArray(length / 2)
            var i = 0
            while (i < length) {
                bytes[i / 2] = ((Character.digit(value[i], 16) shl 4) + Character.digit(value[i + 1], 16)).toByte()
                i += 2
            }
            return bytes
    }

}