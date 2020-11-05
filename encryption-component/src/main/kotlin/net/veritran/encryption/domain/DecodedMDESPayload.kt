package net.veritran.encryption.domain

import net.veritran.encryption.domain.encoding.EncodingValues
import net.veritran.encryption.infrastructure.StringUtils.decode


class DecodedMDESPayload(val messageBytes: ByteArray, val keyBytes: ByteArray, val ivBytes: ByteArray){

    companion object Factory {

        private val encoding =  EncodingValues.HEX

        fun create(encryptedData: String, encryptedKey: String, initialVector: String): DecodedMDESPayload {
            val messageBytes = decode(encryptedData, encoding)
            val keyBytes = decode(encryptedKey,encoding)
            val ivBytes = decode(initialVector, encoding)
            return DecodedMDESPayload(messageBytes, keyBytes, ivBytes)
        }

    }

}