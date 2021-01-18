package net.veritran.encryption.action.payload.mastercard

import com.beust.klaxon.Klaxon
import net.veritran.encryption.domain.encoding.DecryptorPkcs5Padding
import net.veritran.encryption.domain.encoding.KeyFinder
import net.veritran.encryption.domain.encoding.UnWrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.domain.mastercard.EncryptedMastercardPayload
import net.veritran.encryption.infrastructure.hexDecode

class DecryptorMastercardPayload(private val keyFinder: KeyFinder) {

    private fun String.toMastercardEncryptedPayload() =
        Klaxon().parse<EncryptedMastercardPayload>(this)

    fun execute(encryptedMessage: String, publicKey: String): String {
        return encryptedMessage.toMastercardEncryptedPayload()
            .let(::checkNotNull)
            .let { (_, encryptedKey, _, iv, encryptedData) ->
                val unWrapper = publicKey.let(keyFinder::find).let(::UnWrapperOaepWithMgf1WhichUsesSha256MD)
                val privateKey = unWrapper use encryptedKey.hexDecode()
                return DecryptorPkcs5Padding(privateKey, iv.hexDecode()) use encryptedData
            }
    }

}