package net.veritran.encryption.action.payload.mastercard

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.adapter.driven.AesCbcPkcs5PaddingDecryptor
import net.veritran.encryption.infrastructure.hexDecode
import net.veritran.encryption.port.driven.KeyLoader
import net.veritran.encryption.infrastructure.adapter.driven.UnWrapperOaepWithMgf1WhichUsesSha256MD as UnwrapperMGF1

class DecryptorMastercardPayload(private val keyLoader: KeyLoader) {

    private fun String.toMastercardEncryptedPayload() =
        Klaxon().parse<EncryptedMastercardPayload>(this)

    fun execute(encryptedMessage: String, publicKey: String): String {
        return encryptedMessage.toMastercardEncryptedPayload()
            .let(::checkNotNull)
            .let { (_, encryptedKey, _, iv, encryptedData) ->
                val unWrapper = publicKey.let(keyLoader::from).let(::UnwrapperMGF1)
                val privateKey = unWrapper invoke encryptedKey.hexDecode()
                return AesCbcPkcs5PaddingDecryptor(privateKey, iv.hexDecode()).invoke(encryptedData)
            }
    }

}