package action

import net.veritran.encryption.action.EncryptMDESPayload

import org.junit.jupiter.api.Assertions

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

import utils.MDESFixture.aDecryptedBody
import utils.MDESFixture.aKey

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EncryptMDESPayloadTest {

    private val encryptMDESPayload = EncryptMDESPayload()

    private lateinit var expectedEncryptedString: String
    private lateinit var encryptedPayload: String

    @Test
    fun encrypt_mastercard_payload_successfully() {
        when_encrypt_a_mastercard_decrypted_payload()
        then_returns_a_mastercard_encrypted_payload()
    }

    private fun when_encrypt_a_mastercard_decrypted_payload() {
        encryptedPayload = encryptMDESPayload.execute(aDecryptedBody.toString(), aKey)
    }

    private fun then_returns_a_mastercard_encrypted_payload() {
        Assertions.assertEquals(expectedEncryptedString, encryptedPayload)
    }

}