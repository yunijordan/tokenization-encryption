package net.veritran.encryption.action.payload.istp

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.adapter.outbound.AesCbcPkcs5PaddingDecryptor
import net.veritran.encryption.infrastructure.adapter.outbound.UnWrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.infrastructure.hexDecode
import net.veritran.encryption.port.inbound.CipherAction
import net.veritran.encryption.port.outbound.keys.CipherKeyLoader
import java.util.*

class DecryptorItsp(
    private val privateItspKeyLoader: PrivateItspKeyLoader
) : CipherAction {

    private fun String.toMastercardEncryptedPayload() = Klaxon().parse<EncryptedMastercardPayload>(this)

    override fun execute(encryptedMessage: String): String =
        Base64.getDecoder().decode(encryptedMessage).let(::String)
            .toMastercardEncryptedPayload()
            .let(::checkNotNull)
            .let(this::decrypt)

    private fun decrypt(encryptedMastercardPayload: EncryptedMastercardPayload): String {
        val (_, encryptedKey, _, iv, encryptedData) = encryptedMastercardPayload
        val privateKey = privateItspKeyLoader.get()
            .let(::UnWrapperOaepWithMgf1WhichUsesSha256MD) invoke encryptedKey.hexDecode()
        return AesCbcPkcs5PaddingDecryptor(privateKey, iv.hexDecode()).invoke(encryptedData)
    }

    fun interface PrivateItspKeyLoader : CipherKeyLoader

}



