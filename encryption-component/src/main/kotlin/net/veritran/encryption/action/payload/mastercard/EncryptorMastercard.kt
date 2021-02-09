package net.veritran.encryption.action.payload.mastercard

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.adapter.outbound.AesCbcPkcs5PaddingEncryptor
import net.veritran.encryption.infrastructure.hexEncode
import net.veritran.encryption.port.outbound.Encryptor
import net.veritran.encryption.port.outbound.keys.CipherKeyLoader
import java.security.Key
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import net.veritran.encryption.infrastructure.adapter.outbound.WrapperOaepWithMgf1WhichUsesSha256MD as WrapperMGF1

class EncryptorMastercard(private val publicMastercardKeyLoader: MastercardPublicKeyLoader) {

    private fun EncryptedMastercardPayload.toJson() = Klaxon().toJsonString(this)

    private val vector: ByteArray = ByteArray(16)
        .also(SecureRandom.getInstance("SHA1PRNG")::nextBytes)

    private val aes128Key: Key = KeyGenerator.getInstance("AES")
        .also { it.init(128) }
        .generateKey()

    private val encryptor: Encryptor = AesCbcPkcs5PaddingEncryptor(aes128Key, vector)

    fun execute(payload: String): String {
        val encryptedKey = publicMastercardKeyLoader.get()
            .let(::WrapperMGF1)
            .invoke(aes128Key).hexEncode()
        return EncryptedMastercardPayload(
            encryptedKey = encryptedKey,
            iv = vector.hexEncode(),
            encryptedData = encryptor(payload),
        ).toJson()
    }

    fun interface MastercardPublicKeyLoader : CipherKeyLoader

}