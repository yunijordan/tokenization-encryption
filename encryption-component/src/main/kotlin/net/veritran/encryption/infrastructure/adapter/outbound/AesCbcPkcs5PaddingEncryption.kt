package net.veritran.encryption.infrastructure.adapter.outbound

import net.veritran.encryption.infrastructure.hexDecode
import net.veritran.encryption.infrastructure.hexEncode
import net.veritran.encryption.port.outbound.Decryptor
import net.veritran.encryption.port.outbound.Encryptor
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

const val AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5PADDING"
const val MGF1 = "MGF1"

class AesCbcPkcs5PaddingDecryptor (
    private val privateKey: Key,
    private val algorithmParameterSpec: ByteArray
) : Decryptor {
    override fun invoke(encryptedPayload: String): String =
        Cipher.getInstance(AES_CBC_PKCS5PADDING)
            .also { it.init(Cipher.DECRYPT_MODE, privateKey, IvParameterSpec(algorithmParameterSpec)) }
            .doFinal(encryptedPayload.hexDecode())
            .let(::String)
}

class AesCbcPkcs5PaddingEncryptor(
    private val key: Key,
    private val algorithmParameterSpec: ByteArray
) : Encryptor {
    override fun invoke(payload: String): String =
        Cipher.getInstance(AES_CBC_PKCS5PADDING).also {
            it.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(algorithmParameterSpec))
        }.let { it.doFinal(payload.toByteArray()) }.hexEncode()

}

