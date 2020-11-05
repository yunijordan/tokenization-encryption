package net.veritran.encryption.action

import net.veritran.encryption.domain.encoding.EncodingValues

import net.veritran.encryption.infrastructure.EncryptUtils.decrypt
import net.veritran.encryption.infrastructure.EncryptUtils.generateIv
import net.veritran.encryption.infrastructure.EncryptUtils.unwrap

import net.veritran.encryption.infrastructure.StringUtils.decode

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
        val encoding = EncodingValues.HEX
        val messageBytes = decode(encryptedData, encoding)
        val keyBytes = decode(encryptedKey, encoding)
        val ivBytes = decode(initialVector, encoding)
        val privateKey = unwrap(privateTspKey, keyBytes, oaepHashingAlgorithm)
        return decrypt(messageBytes, privateKey, cipherTransformation, generateIv(ivBytes))
    }

}