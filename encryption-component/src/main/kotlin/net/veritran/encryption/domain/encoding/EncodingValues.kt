package net.veritran.encryption.domain.encoding

import net.veritran.encryption.infrastructure.hexDecode
import net.veritran.encryption.infrastructure.hexEncode
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.security.Key
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
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

fun interface UnWrapper {
    infix fun use(wrappedMessage: ByteArray): Key
}

fun interface Wrapper {
    infix fun use(key: Key): ByteArray
}

interface Encryptor {
    infix fun use(payload: String): String
}

interface Decryptor {
    infix fun use(payload: String): String
}

class DecryptorPkcs5Padding(
    private val privateKey: Key,
    private val algorithmParameterSpec: ByteArray
) : Decryptor {
    override fun use(payload: String): String {
        val cipher = Cipher.getInstance(AES_CBC_PKCS5PADDING)
        cipher.init(Cipher.DECRYPT_MODE, privateKey, IvParameterSpec(algorithmParameterSpec))
        return String(cipher.doFinal(payload.hexDecode()))
    }
}

class EncryptorSha256(
    private val privateKey: Key,
    private val ivBytes: ByteArray
) : Encryptor {
    override infix fun use(payload: String): String {
        return Cipher.getInstance(AES_CBC_PKCS5PADDING).also {
            it.init(Cipher.ENCRYPT_MODE, privateKey, IvParameterSpec(ivBytes))
        }.let { it.doFinal(payload.toByteArray()) }.hexEncode()
    }
}

class WrapperOaepWithMgf1WhichUsesSha256MD(
    private val publicKey: Key,
) : Wrapper {
    private val cipher = RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING
        .let(Cipher::getInstance).also {
            it.init(Cipher.WRAP_MODE, publicKey, oaepWithMgf1WhichUsesSha256MD)
        }

    override fun use(key: Key): ByteArray {
        return cipher.wrap(key)
    }
}

val oaepWithMgf1WhichUsesSha256MD: AlgorithmParameterSpec =
    OAEPParameterSpec(
        SHA256.digestAlgorithm,
        MGF1,
        SHA256,
        PSource.PSpecified.DEFAULT
    )

class UnWrapperOaepWithMgf1WhichUsesSha256MD(private val privateKey: Key) : UnWrapper {
    private val cipher = RSA_ECB_OAEP_WITH_SHA256_AND_MGF1PADDING
        .let(Cipher::getInstance).also {
            it.init(Cipher.UNWRAP_MODE, privateKey, oaepWithMgf1WhichUsesSha256MD)
        }

    override infix fun use(wrappedMessage: ByteArray): Key {
        return cipher.unwrap(wrappedMessage, AES, Cipher.SECRET_KEY)
    }
}

fun interface KeyFinder {
    fun find(name: String): Key
}

// "src/test/resources/keys/test_key_pkcs8-2048.der"
val classPathPkcs8RsaKeyFinder = KeyFinder {
    it.let(Paths::get).let(Files::readAllBytes)
        .let(::PKCS8EncodedKeySpec)
        .let(KeyFactory.getInstance("RSA")::generatePrivate)
}

val classPathX509CertificateFinder = KeyFinder {
    FileInputStream(it)
        .let(CertificateFactory.getInstance("X.509")::generateCertificate).publicKey
}

