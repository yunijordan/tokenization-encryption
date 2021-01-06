package action.message

import net.veritran.encryption.infrastructure.EncryptUtils.verifySign

import utils.MessageFixture.aHashAlgorithm
import utils.MessageFixture.aMessage
import utils.MessageFixture.aPrivateKey
import utils.MessageFixture.aPublicKey
import utils.MessageFixture.aKeyAlgorithm
import utils.MessageFixture.aValidCipherTransformation

import net.veritran.encryption.action.message.SignMessage

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
        result = sign.execute(aMessage, aPrivateKey, aKeyAlgorithm, aValidCipherTransformation, aHashAlgorithm)!!
    }

    private fun then_the_signed_data_is() {
        assertTrue(verifySign(result, aMessage, aPublicKey, aKeyAlgorithm, aValidCipherTransformation, aHashAlgorithm))
    }

}