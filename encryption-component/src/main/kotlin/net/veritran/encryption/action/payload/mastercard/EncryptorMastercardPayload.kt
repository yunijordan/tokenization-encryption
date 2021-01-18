package net.veritran.encryption.action.payload.mastercard

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.encoding.EncryptorSha256
import net.veritran.encryption.domain.encoding.KeyFinder
import net.veritran.encryption.domain.encoding.WrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.hexEncode
import java.security.Key
import java.security.SecureRandom
import javax.crypto.KeyGenerator

class EncryptorMastercardPayload(private val publicKeyFinder: KeyFinder) {

    private fun EncryptedMastercardPayload.toJson() = Klaxon().toJsonString(this)

    private val vector: ByteArray = ByteArray(16)
        .also(SecureRandom.getInstance("SHA1PRNG")::nextBytes)

    private val aes128Key: Key = KeyGenerator.getInstance("AES")
        .also { it.init(128) }
        .generateKey()

    private val encryptorSha256 = EncryptorSha256(aes128Key, vector)

    fun execute(
        payload: String,
        publicKey: String
    ): String {
        val encryptedKey = publicKeyFinder.find(publicKey)
            .let(::WrapperOaepWithMgf1WhichUsesSha256MD)
            .use(aes128Key).hexEncode()
        return EncryptedMastercardPayload(
            encryptedKey = encryptedKey,
            iv = vector.hexEncode(),
            encryptedData = encryptorSha256 use payload,
        ).toJson()
    }

}