package action.message

import utils.MessageFixture.aMessage
import utils.MessageFixture.aPrivateKey
import utils.MessageFixture.anEncryptedMessage
import utils.MessageFixture.aValidCipherTransformation
import utils.MessageFixture.aKeyAlgorithm
import net.veritran.encryption.action.message.DecryptMessage

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
        result = decryptMessage.execute(
            anEncryptedMessage,
            aPrivateKey,
            aValidCipherTransformation,
            aKeyAlgorithm
        )
    }

    private fun then_the_decrypted_data_is() {
        Assertions.assertEquals(result, aMessage)
    }

}