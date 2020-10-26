package action

import infrastructure.EncryptUtils.verifySign

import action.EncryptFixture.aMessage
import action.EncryptFixture.aPrivateKey
import action.EncryptFixture.aPublicKey

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SignMessageTest {

    private lateinit var result: ByteArray
    private val sign = SignMessage()

    @Test
    fun sign_successfully() {
        when_sign_using_RSA()
        then_the_signed_data_is()
    }

    private fun when_sign_using_RSA() {
        result = sign.execute(aMessage, aPrivateKey)!!
    }

    private fun then_the_signed_data_is() {
        assertTrue(verifySign(result, aMessage, aPublicKey))
    }

}