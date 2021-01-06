package net.veritran.encryption.domain.encoding

import net.veritran.encryption.infrastructure.hexDecode
import net.veritran.encryption.infrastructure.hexEncode
import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

enum class EncodingValues(val value: String) {
    BASE64("BASE64"),
    HEX("HEX")
}

enum class HashAlgorithms(val value: String) {

    SHA_256("SHA-256");

    companion object {
        fun validate(value: String): Boolean {
            return HashAlgorithms.values().any { item -> item.value == value }
        }
    }
}

const val AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING"
const val RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
const val MGF1 = "MGF1"
const val AES = "AES"
val SHA256: MGF1ParameterSpec = MGF1ParameterSpec.SHA256

interface UnWrapper {
    infix fun use(wrappedMessage: ByteArray): Key
}

interface Encryptor {
    infix fun use(payload: String): String
}

interface Decryptor {
    infix fun use(payload: String): String
}

class EncryptorSha256(
    private val publicKey: String,
    private val unWrapper: UnWrapper,
    private val ivBytes: ByteArray
) : Encryptor {

    private val privateKey: Key = publicKey.hexDecode().let(unWrapper::use)

    override infix fun use(payload: String): String {
        return Cipher.getInstance(AES_CBC_PKCS5PADDING).also {
            it.init(Cipher.ENCRYPT_MODE, privateKey, IvParameterSpec(ivBytes))
        }.let { it.doFinal(payload.toByteArray()) }.hexEncode()
    }
}

class UnWrapperOaepWithMgf1WhichUsesSha256MD(private val privateKey: Key) : UnWrapper {
    private val oaepWithMgf1WhichUsesSha256MD: AlgorithmParameterSpec =
        OAEPParameterSpec(
            SHA256.digestAlgorithm,
            MGF1,
            SHA256,
            PSource.PSpecified.DEFAULT
        )
    private val cipher = RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING
        .let(Cipher::getInstance).also {
            it.init(Cipher.UNWRAP_MODE, privateKey, oaepWithMgf1WhichUsesSha256MD)
        }

    override infix fun use(wrappedMessage: ByteArray): Key {
        return cipher.unwrap(wrappedMessage, AES, Cipher.SECRET_KEY)
    }

}

