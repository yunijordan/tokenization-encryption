package net.veritran.encryption.infrastructure

import net.veritran.encryption.domain.encoding.EncodingValues
import java.util.*

fun ByteArray.hexEncode() = StringUtils.hexEncode(this)
fun String.hexDecode() = StringUtils.decode(this, EncodingValues.HEX)
fun String.Base64Decode() = StringUtils.decode(this, EncodingValues.BASE64)

object StringUtils {

    fun decode(
        value: String,
        encoding: EncodingValues? = EncodingValues.BASE64
    ): ByteArray {
        return if (encoding == EncodingValues.HEX)
            hexDecode(value)
        else
            base64Decode(value)
    }

    fun hexEncode(bytes: ByteArray): String {
        val stringBuilder: StringBuilder = StringBuilder(bytes.size * 2)
        bytes.forEach { stringBuilder.append(String.format("%02x", it)) }
        return stringBuilder.toString()
    }

    private fun hexDecode(value: String): ByteArray {
        val bytes = ByteArray(value.length / 2)
        for (i in value.indices step 2) {
            bytes[i / 2] = ((Character.digit(value[i], 16) shl 4) + Character.digit(value[i + 1], 16)).toByte()
        }
        return bytes
    }

    private fun base64Decode(value: String): ByteArray = Base64.getDecoder().decode(value.toByteArray())

}