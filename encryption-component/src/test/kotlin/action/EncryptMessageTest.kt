package action

import net.veritran.encryption.action.EncryptMessage
import net.veritran.encryption.infrastructure.EncryptUtils

import action.EncryptFixture.aMessage
import action.EncryptFixture.aPrivateKey
import action.EncryptFixture.aCipherTransformation
import action.EncryptFixture.aKeyAlgorithm
import action.EncryptFixture.anInvalidAlgorithm
import net.veritran.encryption.domain.error.InvalidAlgorithm

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class EncryptMessageTest {

    private lateinit var result: String
    private lateinit var exception: Exception

    @Test
    fun encrypt_message_successfully() {
        when_encrypt_message(aKeyAlgorithm)
        then_the_encrypted_data_is()
    }

    @Test()
    fun encrypt_message_with_unknown_key_algorithm_fails() {
        val exception: InvalidAlgorithm = assertThrows{
            when_encrypt_message(anInvalidAlgorithm)
        }
        assertEquals(exception.message, "Invalid algorithm")

    }

    private fun when_encrypt_message(keyAlgorithm: String) {
        result =
            EncryptMessage.execute(
                aMessage,
                EncryptFixture.aPublicKey,
                aCipherTransformation,
                keyAlgorithm)
    }

    private fun then_the_encrypted_data_is() {
        Assertions.assertEquals(
            aMessage,
            EncryptUtils.decrypt(result, aPrivateKey, aCipherTransformation, aKeyAlgorithm)
        )
    }

}