package action

import action.EncryptFixture.aHashedMessage
import action.EncryptFixture.aMessage
import action.EncryptFixture.aPublicKey
import action.EncryptFixture.anAlgorithm

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
        result = verifySignature.execute(aHashedMessage, aMessage, aPublicKey, anAlgorithm)
    }

    private fun then_the_signed_data_is() {
        assertTrue(result)
    }

}