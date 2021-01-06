package action.jwe

import utils.MessageFixture.aPrivateKey_2048
import utils.MessageFixture.aKeyAlgorithm
import utils.MessageFixture.anEncryptedJwe

import net.veritran.encryption.action.jwe.UnwrapJWE

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class GetJwePayloadTest {
    lateinit var decryptedPayload: String
    var expectedDecryptedPayload = "{\t\n\taccountNumber:\"5549567364399928\"\n}"

    @Test
    fun get_payload_from_token_successfully() {
        when_an_asymmetric_decrypt_action_is_called()
        then_we_have_a_decrypted_payload()
    }

    private fun when_an_asymmetric_decrypt_action_is_called() {
        decryptedPayload = UnwrapJWE().execute(anEncryptedJwe, aPrivateKey_2048, aKeyAlgorithm)
    }

    private fun then_we_have_a_decrypted_payload() {
        Assertions.assertTrue(decryptedPayload == expectedDecryptedPayload)
    }
}