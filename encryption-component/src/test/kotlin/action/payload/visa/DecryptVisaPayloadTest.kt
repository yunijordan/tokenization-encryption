package action.payload.visa

import net.veritran.encryption.action.payload.visa.DecryptVisaPayload

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import utils.VisaFixture.aDecryptionPrivateKey
import utils.VisaFixture.aSignaturePublicKey
import utils.VisaFixture.aValidJws
import utils.VisaFixture.decryptedPayloadExpected

class DecryptVisaPayloadTest {

    private lateinit var decryptedPayloadResult: String
    private var decryptVisaPayload = DecryptVisaPayload()

    @Test
    fun `Decrypt a Visa payload successfully`() {
        when_decrypt_a_jwe_payload()
        then_returns_a_decrypted_payload()
    }

    private fun when_decrypt_a_jwe_payload() {
        decryptedPayloadResult = decryptVisaPayload.execute(aValidJws, aSignaturePublicKey, aDecryptionPrivateKey)
    }

    private fun then_returns_a_decrypted_payload() =
        Assertions.assertEquals(decryptedPayloadExpected, decryptedPayloadResult)

}