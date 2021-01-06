package net.veritran.encryption.action.mastercardPayload

import net.veritran.encryption.domain.DecodedMastercardPayload.Factory.create

import net.veritran.encryption.infrastructure.EncryptUtils.decrypt
import net.veritran.encryption.infrastructure.EncryptUtils.generateIv
import net.veritran.encryption.infrastructure.EncryptUtils.unwrap

import java.security.Key

class DecryptMastercardPayload {

    fun execute(
        encryptedData: String,
        encryptedKey: String,
        oaepHashingAlgorithm: String,
        initializationVector: String,
        cipherTransformation: String,
        privateTspKey: Key
    ): String {
        val decodedPayload = create(encryptedData, encryptedKey, initializationVector)
        val privateKey = unwrap(decodedPayload.wrappedKey(), privateTspKey, oaepHashingAlgorithm)
        val iv = generateIv(decodedPayload.iv())
        return decrypt(decodedPayload.encryptedData(), privateKey, cipherTransformation, iv)
    }

}