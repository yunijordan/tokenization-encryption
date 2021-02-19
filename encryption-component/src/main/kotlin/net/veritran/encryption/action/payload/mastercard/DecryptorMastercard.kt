package net.veritran.encryption.action.payload.mastercard

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.adapter.outbound.AesCbcPkcs5PaddingDecryptor
import net.veritran.encryption.infrastructure.hexDecode
import net.veritran.encryption.port.inbound.CipherAction
import net.veritran.encryption.port.outbound.keys.CipherKeyLoader
import net.veritran.encryption.infrastructure.adapter.outbound.UnWrapperOaepWithMgf1WhichUsesSha256MD as UnwrapperMGF1

class DecryptorMastercard(
    private val privateMastercardKeyLoader: MastercardPrivateKeyLoader
) : CipherAction {

    private fun String.toMastercardEncryptedPayload() = Klaxon().parse<EncryptedMastercardPayload>(this)

    override fun execute(encryptedMessage: String): String = encryptedMessage.toMastercardEncryptedPayload()
        .let(::checkNotNull)
        .let { (_, encryptedKey, _, iv, encryptedData) ->
            val privateKey = privateMastercardKeyLoader.get().let(::UnwrapperMGF1) invoke encryptedKey.hexDecode()
            return AesCbcPkcs5PaddingDecryptor(privateKey, iv.hexDecode()).invoke(encryptedData)
        }


    fun interface MastercardPrivateKeyLoader : CipherKeyLoader

}