package action.payload.visa

import net.veritran.encryption.action.payload.visa.DecryptVisaPayload

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class DecryptVisaPayloadTest {

    private lateinit var decryptedResult: String
    private val decryptVisaPayload = DecryptVisaPayload()

    @Test
    fun decrypt_visa_payload_successfully() {
        when_decrypt_a_visa_encrypted_payload()
        then_returns_a_visa_decrypted_payload()
    }

    private fun when_decrypt_a_visa_encrypted_payload() {
        decryptedResult = decryptVisaPayload.execute()
    }

    private fun then_returns_a_visa_decrypted_payload() {
        Assertions.assertTrue(decryptedResult.contains(""))
    }

}