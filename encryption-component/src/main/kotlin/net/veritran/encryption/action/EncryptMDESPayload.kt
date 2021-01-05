package net.veritran.encryption.action

import net.veritran.encryption.domain.algorithm.CipherTransformations
import net.veritran.encryption.domain.algorithm.HashAlgorithms
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.domain.encoding.*
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.StringUtils
import net.veritran.encryption.infrastructure.getHexEncode
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

class EncryptMDESPayload(
    private val payload: String,
    private val key: String,
    private val tspKey: ByteArray
) {

    lateinit var initialVector: String
        private set

    private val unwrapping: UnWrapper = UnWrapperOaepWithMgf1WhichUsesSha256MD(
        EncryptUtils.getPrivateKey(
            tspKey,
            KeyAlgorithms.RSA.value
        )
    )

    private val encryptor: Encryptor = MDesEncryptor()

    fun execute(): String {
        val ivBytes = ivBytes().also { initialVector = it.getHexEncode() }
        /*
         */
        return Cipher.getInstance(CipherTransformations.AES_CBC_PKCS5PADDING.value).also {
            it.init(Cipher.ENCRYPT_MODE, generateKey(key, HashAlgorithms.SHA_256.value), IvParameterSpec(ivBytes))
        }.let { it.doFinal(payload.toByteArray()) }.getHexEncode()
        /*
        return encryptor.use(payload.toByteArray()).getHexEncode()
         */
    }

    private fun generateKey(publicKey: String, keyAlgorithm: String) =
        StringUtils.decode(publicKey, EncodingValues.HEX)
            .let { unwrapping use it }

    private fun ivBytes(): ByteArray {
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        return ivBytes
    }

}