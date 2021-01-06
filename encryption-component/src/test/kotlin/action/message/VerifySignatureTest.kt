package action.message

import utils.MessageFixture.aHashAlgorithm
import utils.MessageFixture.aHashedMessage
import utils.MessageFixture.aMessage
import utils.MessageFixture.aPublicKey
import utils.MessageFixture.aKeyAlgorithm
import utils.MessageFixture.aValidCipherTransformation

import net.veritran.encryption.action.message.VerifySignature

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VerifySignatureTest {

    private var result = false
    private val verifySignature = VerifySignature()

    @Test
    fun sign_successfully() {
        when_verify_sign_using_RSA()
        then_the_signed_data_is()
    }

    private fun when_verify_sign_using_RSA() {
        result = verifySignature.execute(
            aHashedMessage,
            aMessage,
            aPublicKey,
            aKeyAlgorithm,
            aValidCipherTransformation,
            aHashAlgorithm
        )
    }

    private fun then_the_signed_data_is() {
        assertTrue(result)
    }

}