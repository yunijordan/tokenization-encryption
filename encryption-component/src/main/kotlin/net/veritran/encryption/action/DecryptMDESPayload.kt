package net.veritran.encryption.action

import net.veritran.encryption.domain.DecodedMDESPayload.Factory.create

import net.veritran.encryption.infrastructure.EncryptUtils.decrypt
import net.veritran.encryption.infrastructure.EncryptUtils.generateIv
import net.veritran.encryption.infrastructure.EncryptUtils.unwrap

import java.security.Key

class DecryptMDESPayload {

    fun execute(
        encryptedData: String,
        encryptedKey: String,
        oaepHashingAlgorithm: String,
        initialVector: String,
        cipherTransformation: String,
        privateTspKey: Key
    ): String {
        val decodedPayload = create(encryptedData, encryptedKey, initialVector)
        val privateKey = unwrap(privateTspKey, decodedPayload.keyBytes, oaepHashingAlgorithm)
        val iv = generateIv(decodedPayload.ivBytes)
        return decrypt(decodedPayload.messageBytes, privateKey, cipherTransformation, iv)
    }


}