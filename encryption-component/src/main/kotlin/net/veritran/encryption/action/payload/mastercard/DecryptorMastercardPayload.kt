package net.veritran.encryption.action.payload.mastercard

import net.veritran.encryption.domain.encoding.DecryptorPkcs5Padding
import net.veritran.encryption.domain.encoding.KeyFinder
import net.veritran.encryption.domain.encoding.UnWrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.infrastructure.hexDecode

class DecryptorMastercardPayload(private val keyFinder: KeyFinder) {

    fun execute(
        encryptedData: String,
        encryptedKey: String,
        iv: String,
        privateTspKey: String
    ): String {
        val unWrapper = UnWrapperOaepWithMgf1WhichUsesSha256MD(keyFinder.find(privateTspKey))
        val privateKey = unWrapper.use(encryptedKey.hexDecode())
        return DecryptorPkcs5Padding(privateKey, iv.hexDecode()).use(encryptedData)
    }

}