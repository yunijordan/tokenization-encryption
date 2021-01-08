package net.veritran.encryption.domain

import net.veritran.encryption.domain.encoding.EncodingValues
import net.veritran.encryption.infrastructure.StringUtils.decode

class DecodedMastercardPayload(
    private val decodedEncryptedData: ByteArray,
    private val decodedEncryptedKey: ByteArray,
    private val decodedIV: ByteArray
){

    fun getDecodedEncryptedData(): ByteArray = decodedEncryptedData
    fun getDecodedEncryptedKey(): ByteArray = decodedEncryptedKey
    fun getDecodedIV(): ByteArray = decodedIV

    companion object Factory {

        private val encoding =  EncodingValues.HEX

        fun create(payload: String, encryptedKey: String, initializationVector: String): DecodedMastercardPayload {
            val decodedEncryptedData = decode(payload, encoding)
            val decodedEncryptedKey = decode(encryptedKey,encoding)
            val decodedIV = decode(initializationVector, encoding)
            return DecodedMastercardPayload(decodedEncryptedData, decodedEncryptedKey, decodedIV)
        }

    }

}