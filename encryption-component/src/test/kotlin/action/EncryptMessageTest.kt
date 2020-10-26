package action

import action.action.EncryptMessage
import infrastructure.EncryptUtils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class EncryptMessageTest {
    private lateinit var result: String
    private val encryptMessage = EncryptMessage()

    @Test
    fun encrypt_successfully() {
        when_encrypt_using_RSA()
        then_the_encrypted_data_is()
    }

    private fun when_encrypt_using_RSA() {
        result = encryptMessage.execute(EncryptFixture.aMessage, EncryptFixture.aPublicKey)
    }

    private fun then_the_encrypted_data_is() {
        Assertions.assertEquals(EncryptFixture.aMessage, EncryptUtils.decrypt(result, EncryptFixture.aPrivateKey))
    }
}