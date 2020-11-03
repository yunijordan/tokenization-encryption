package action

import utils.EncryptFixture.aHashAlgorithm
import net.veritran.encryption.infrastructure.EncryptUtils.verifySign

import utils.EncryptFixture.aMessage
import utils.EncryptFixture.aPrivateKey
import utils.EncryptFixture.aPublicKey
import utils.EncryptFixture.aKeyAlgorithm
import utils.EncryptFixture.aValidCipherTransformation

import net.veritran.encryption.action.SignMessage

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