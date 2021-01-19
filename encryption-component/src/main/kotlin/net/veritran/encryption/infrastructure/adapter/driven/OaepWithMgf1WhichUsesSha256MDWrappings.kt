package net.veritran.encryption.infrastructure.adapter.driven


import net.veritran.encryption.port.driven.Unwrapper
import net.veritran.encryption.port.driven.Wrapper
import java.security.Key
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec.SHA256
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

const val RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"
const val AES = "AES"

class WrapperOaepWithMgf1WhichUsesSha256MD(
    private val publicKey: Key,
) : Wrapper {
    private val cipher = RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING
        .let(Cipher::getInstance).also {
            it.init(Cipher.WRAP_MODE, publicKey, oaepWithMgf1WhichUsesSha256MD)
        }

    override fun invoke(key: Key): ByteArray {
        return cipher.wrap(key)
    }
}


class UnWrapperOaepWithMgf1WhichUsesSha256MD(private val privateKey: Key) : Unwrapper {
    private val cipher = RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING
        .let(Cipher::getInstance).also {
            it.init(Cipher.UNWRAP_MODE, privateKey, oaepWithMgf1WhichUsesSha256MD)
        }

    override infix fun invoke(wrappedMessage: ByteArray): Key {
        return cipher.unwrap(wrappedMessage, AES, Cipher.SECRET_KEY)
    }
}

val oaepWithMgf1WhichUsesSha256MD: AlgorithmParameterSpec = OAEPParameterSpec(
    SHA256.digestAlgorithm,
    MGF1,
    SHA256,
    PSource.PSpecified.DEFAULT
)