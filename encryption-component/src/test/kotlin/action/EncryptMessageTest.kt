package action

import net.veritran.encryption.action.EncryptMessage
import net.veritran.encryption.infrastructure.EncryptUtils

import utils.EncryptFixture.aMessage
import utils.EncryptFixture.aPublicKey
import utils.EncryptFixture.aPrivateKey
import utils.EncryptFixture.aValidCipherTransformation
import utils.EncryptFixture.aKeyAlgorithm
import utils.EncryptFixture.anInvalidValue

import net.veritran.encryption.domain.error.DomainError
import net.veritran.encryption.infrastructure.EncryptUtils.getPrivateKey
import net.veritran.encryption.infrastructure.StringUtils.decode

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test

import kotlin.test.assertEquals

class EncryptMessageTest {

    private lateinit var result: String

    @Test
    fun encrypt_message_successfully() {
        when_encrypt_message(aKeyAlgorithm, aValidCipherTransformation)
        then_the_encrypted_data_is()
    }

    @Test
    fun encrypt_message_with_invalid_key_algorithm_fails() {
        val exception: DomainError = assertThrows{
            when_encrypt_message(anInvalidValue, aValidCipherTransformation)
        }
        assertEquals(exception.message, "Invalid algorithm")
    }

    @Test
    fun encrypt_message_with_invalid_cipher_transformation_fails() {
        val exception: DomainError = assertThrows{
            when_encrypt_message(aKeyAlgorithm, anInvalidValue)
        }
        assertEquals(exception.message, "Invalid transformation")
    }

    private fun when_encrypt_message(keyAlgorithm: String, cipherTransformation: String) {
        result = EncryptMessage.execute(
            aMessage,
            aPublicKey,
            cipherTransformation,
            keyAlgorithm
        )
    }

    private fun then_the_encrypted_data_is() {
        Assertions.assertEquals(
            aMessage,
            EncryptUtils.decrypt(
                decode(result),
                getPrivateKey(aPrivateKey, aKeyAlgorithm),
                aValidCipherTransformation
            )
        )
    }

}