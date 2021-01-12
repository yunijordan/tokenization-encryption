package net.veritran.encryption.action.payload.mastercard

import net.veritran.encryption.domain.encoding.EncryptorSha256
import net.veritran.encryption.domain.encoding.KeyFinder
import net.veritran.encryption.domain.encoding.WrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.infrastructure.hexEncode
import java.security.Key
import java.security.SecureRandom
import javax.crypto.KeyGenerator

class EncrypterMastercardPayload(
    private val payload: String,
    private val publicKeyFinder: KeyFinder
) {

    val vector: ByteArray = ByteArray(16)
        .also(SecureRandom.getInstance("SHA1PRNG")::nextBytes)

    private val aes128Key: Key = KeyGenerator.getInstance("AES")
        .also { it.init(128) }
        .generateKey()

    lateinit var encryptedKey: String
        private set

    fun execute(
        publicKey: String
    ): String {
        publicKeyFinder.find(publicKey).let(::WrapperOaepWithMgf1WhichUsesSha256MD)
            .use(aes128Key).also { encryptedKey = it.hexEncode() }
        return EncryptorSha256(
            aes128Key,
            vector
        ) use payload
    }

}