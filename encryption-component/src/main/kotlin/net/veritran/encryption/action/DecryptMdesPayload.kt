package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils.decryptData
import net.veritran.encryption.infrastructure.EncryptUtils.getUnwrappedKey
import net.veritran.encryption.infrastructure.StringUtils.decodeHexToBytes
import java.nio.charset.StandardCharsets
import java.security.Key

class DecryptMdesPayload {

    fun execute(
        encryptedData: String,
        encryptedAesKey: String,
        oaepHashingAlgorithm: String,
        initialVector: String,
        privateTspKey: Key
    ): String {
        val encryptedDataBytes = decodeHexToBytes(encryptedData)
        val unwrappedKey = getUnwrappedKey(privateTspKey, encryptedAesKey, oaepHashingAlgorithm)
        val decryptedBytes = decryptData(unwrappedKey, initialVector, encryptedDataBytes)
        return String(decryptedBytes, StandardCharsets.UTF_8)
    }
}