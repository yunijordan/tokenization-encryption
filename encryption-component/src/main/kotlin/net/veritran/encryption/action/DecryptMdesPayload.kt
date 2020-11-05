package net.veritran.encryption.action

import net.veritran.encryption.domain.algorithm.CipherTransformations

import net.veritran.encryption.infrastructure.EncryptUtils.decrypt
import net.veritran.encryption.infrastructure.EncryptUtils.generateIv
import net.veritran.encryption.infrastructure.EncryptUtils.unwrap
import net.veritran.encryption.infrastructure.StringUtils.decodeHexToBytes

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
        val encryptedAesKeyBytes = decodeHexToBytes(encryptedAesKey)
        val unwrappedKey = unwrap(privateTspKey, encryptedAesKeyBytes, oaepHashingAlgorithm)
        val initialVectorParam = generateIv(initialVector)
        return decrypt(encryptedDataBytes, unwrappedKey, CipherTransformations.AES_CBC_PKCS5PADDING.value, initialVectorParam)
    }

}