package net.veritran.encryption.action.payload.mastercard

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.adapter.driven.AesCbcPkcs5PaddingEncryptor
import net.veritran.encryption.infrastructure.hexEncode
import net.veritran.encryption.port.driven.Encryptor
import net.veritran.encryption.port.driven.KeyLoader
import java.security.Key
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import net.veritran.encryption.infrastructure.adapter.driven.WrapperOaepWithMgf1WhichUsesSha256MD as WrapperMGF1

class EncryptorMastercardPayload(private val keyLoader: KeyLoader) {

    private fun EncryptedMastercardPayload.toJson() = Klaxon().toJsonString(this)

    private val vector: ByteArray = ByteArray(16)
        .also(SecureRandom.getInstance("SHA1PRNG")::nextBytes)

    private val aes128Key: Key = KeyGenerator.getInstance("AES")
        .also { it.init(128) }
        .generateKey()

    private val encryptor: Encryptor = AesCbcPkcs5PaddingEncryptor(aes128Key, vector)

    fun execute(
        payload: String,
        publicKey: String
    ): String {
        val encryptedKey = keyLoader.from(publicKey)
            .let(::WrapperMGF1)
            .invoke(aes128Key).hexEncode()
        return EncryptedMastercardPayload(
            encryptedKey = encryptedKey,
            iv = vector.hexEncode(),
            encryptedData = encryptor(payload),
        ).toJson()
    }

}