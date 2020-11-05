package net.veritran.encryption.infrastructure

import net.veritran.encryption.domain.encoding.EncodingValues
import java.util.*

object StringUtils {

    fun decode(
        value: String,
        encoding: EncodingValues? = EncodingValues.BASE64
    ): ByteArray{
        return if(encoding == EncodingValues.HEX)
                    decodeHex(value)
               else
                    decodeBase64(value)
    }

    private fun decodeHex(value: String): ByteArray {
        val bytes = ByteArray(value.length / 2)
        for (i in value.indices step 2) {
            bytes[i/2] = ((Character.digit(value[i], 16) shl 4) + Character.digit(value[i+1], 16)).toByte()
        }
        return bytes
    }

    private fun decodeBase64(value: String): ByteArray = Base64.getDecoder().decode(value.toByteArray())

}