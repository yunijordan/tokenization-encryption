package net.veritran.encryption.domain.encoding

import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
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

const val MGF1 = "MGF1"
const val AES = "AES"
val SHA256: MGF1ParameterSpec = MGF1ParameterSpec.SHA256

interface UnWrapper {
    infix fun use(wrappedMessage: ByteArray): Key
}

interface Encryptor {
    infix fun use(message: ByteArray): ByteArray
}

class MDesEncryptor: Encryptor {
    override infix fun use(message: ByteArray): ByteArray = ByteArray(16)
}

class UnWrapperOaepWithMgf1WhichUsesSha256MD(private val privateKey: Key) : UnWrapper {
    private val oaepWithMgf1WhichUsessha256MD: AlgorithmParameterSpec =
        OAEPParameterSpec(
            SHA256.digestAlgorithm,
            MGF1,
            SHA256,
            PSource.PSpecified.DEFAULT
        )
    private val cipher = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
        .let(Cipher::getInstance).also {
            it.init(Cipher.UNWRAP_MODE, privateKey, oaepWithMgf1WhichUsessha256MD)
        }

    override infix fun use(wrappedMessage: ByteArray): Key {
        return cipher.unwrap(wrappedMessage, AES, Cipher.SECRET_KEY)
    }

}

