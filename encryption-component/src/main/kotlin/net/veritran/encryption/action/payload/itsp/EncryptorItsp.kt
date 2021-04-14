package net.veritran.encryption.action.payload.itsp

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.adapter.outbound.AesCbcPkcs5PaddingEncryptor
import net.veritran.encryption.infrastructure.adapter.outbound.WrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.infrastructure.hexEncode
import net.veritran.encryption.port.inbound.CipherAction
import net.veritran.encryption.port.outbound.Encryptor
import net.veritran.encryption.port.outbound.keys.CipherKeyLoader
import java.security.Key
import java.security.SecureRandom
import java.util.*
import javax.crypto.KeyGenerator

class EncryptorItsp(
    private val itspPublicKeyLoader: PublicItspKeyLoader
) : CipherAction {

    private fun EncryptedMastercardPayload.toJson() = Klaxon().toJsonString(this)

    private val vector: ByteArray = ByteArray(16)
        .also(SecureRandom.getInstance("SHA1PRNG")::nextBytes)

    private val aes128Key: Key = KeyGenerator.getInstance("AES")
        .also { it.init(128) }
        .generateKey()

    private val encryptor: Encryptor = AesCbcPkcs5PaddingEncryptor(aes128Key, vector)

    override fun execute(payload: String): String {
        val encryptedKey = itspPublicKeyLoader.get()
            .let(::WrapperOaepWithMgf1WhichUsesSha256MD)
            .invoke(aes128Key).hexEncode()
        return EncryptedMastercardPayload(
            encryptedKey = encryptedKey,
            iv = vector.hexEncode(),
            encryptedData = encryptor(payload),
        ).toJson().let { Base64.getEncoder().encodeToString(it.toByteArray()) }
    }

    fun interface PublicItspKeyLoader : CipherKeyLoader
}