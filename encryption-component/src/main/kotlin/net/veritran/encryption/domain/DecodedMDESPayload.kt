package net.veritran.encryption.domain

import net.veritran.encryption.domain.encoding.EncodingValues
import net.veritran.encryption.infrastructure.StringUtils.decode

class DecodedMDESPayload(
    private val encryptedDataBytes: ByteArray,
    private val wrappedKeyBytes: ByteArray,
    private val ivBytes: ByteArray
){

    fun encryptedData(): ByteArray = encryptedDataBytes
    fun wrappedKey(): ByteArray = wrappedKeyBytes
    fun iv(): ByteArray = ivBytes

    companion object Factory {

        private val encoding =  EncodingValues.HEX

        fun create(payload: String, encryptedKey: String, initializationVector: String): DecodedMDESPayload {
            val decodedEncryptedData = decode(payload, encoding)
            val decodedEncryptedKey = decode(encryptedKey,encoding)
            val decodedIV = decode(initializationVector, encoding)
            return DecodedMDESPayload(decodedEncryptedData, decodedEncryptedKey, decodedIV)
        }

    }

}