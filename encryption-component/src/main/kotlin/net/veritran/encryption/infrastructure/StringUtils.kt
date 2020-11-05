package net.veritran.encryption.infrastructure

import java.util.*

object StringUtils {

    fun decodeHexToBytes(value: String): ByteArray {
        val bytes = ByteArray(value.length / 2)
        for ( i in 0..value.length-1 step 2) {
            bytes[i / 2] = ((Character.digit(value[i], 16) shl 4) + Character.digit(value[i + 1], 16)).toByte()
        }
        return bytes
    }

      fun decodeBase64ToBytes(key:String): ByteArray {
        return Base64.getDecoder().decode(key.toByteArray())
    }
}