package action

import EncryptMessage
import infrastructure.EncryptUtils

import action.EncryptFixture.aMessage
import action.EncryptFixture.aPrivateKey
import action.EncryptFixture.pkcs1paddingTransformation

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
        result = encryptMessage.execute(aMessage, EncryptFixture.aPublicKey, pkcs1paddingTransformation)
    }

    private fun then_the_encrypted_data_is() {
        Assertions.assertEquals(aMessage, EncryptUtils.decrypt(result, aPrivateKey, pkcs1paddingTransformation))
    }

}