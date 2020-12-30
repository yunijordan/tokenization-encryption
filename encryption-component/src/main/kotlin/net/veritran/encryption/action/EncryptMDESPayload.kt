package net.veritran.encryption.action

import net.veritran.encryption.domain.algorithm.CipherTransformations
import net.veritran.encryption.domain.algorithm.HashAlgorithms
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.domain.encoding.EncodingValues
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.StringUtils
import net.veritran.encryption.infrastructure.StringUtils.hexEncode
import java.security.Key
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

class EncryptMDESPayload(private val payload: String, private val key: String, private val tspKey: ByteArray) {

    fun execute() = encrypt(
        payload,
        key,
        CipherTransformations.AES_CBC_PKCS5PADDING.value,
        HashAlgorithms.SHA_256.value, ivBytes()
    ).let(::hexEncode)

    private fun encrypt(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String,
        ivBytes: ByteArray?
    ): ByteArray {
        return cipherMessage(
            cipherTransformation,
            message.toByteArray(),
            Cipher.ENCRYPT_MODE,
            generateKey(publicKey, keyAlgorithm),
            IvParameterSpec(ivBytes)
        )
    }

    private fun generateKey(publicKey: String, keyAlgorithm: String) =
        StringUtils.decode(publicKey, EncodingValues.HEX)
            .let { EncryptUtils.unwrap(it, EncryptUtils.getPrivateKey(tspKey, KeyAlgorithms.RSA.value), keyAlgorithm) }

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

    private fun ivBytes(): ByteArray {
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        return ivBytes
    }

}