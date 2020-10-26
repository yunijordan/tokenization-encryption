package action

import action.EncryptFixture.aMessage
import action.EncryptFixture.aPrivateKey
import action.EncryptFixture.anEncryptedMessage

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class DecryptMessageTest {

    private lateinit var result: String
    private val decryptMessage = DecryptMessage()

    @Test
    fun decrypt_successfully() {
        when_decrypt_using_RSA()
        then_the_decrypted_data_is()
    }

    private fun when_decrypt_using_RSA() {
        result = decryptMessage.execute(anEncryptedMessage, aPrivateKey)
    }

    private fun then_the_decrypted_data_is() {
        Assertions.assertEquals(result, aMessage)
    }

}