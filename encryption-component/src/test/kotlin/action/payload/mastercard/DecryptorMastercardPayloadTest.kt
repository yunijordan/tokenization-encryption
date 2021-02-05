package action.payload.mastercard

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercardPayload
import net.veritran.encryption.infrastructure.adapter.outbound.classPathPkcs8RsaPrivateKeyLoader
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import utils.MastercardFixture.aDecryptedBody
import utils.MastercardFixture.encryptedBody
import utils.MastercardFixture.keyFilePath

class DecryptorMastercardPayloadTest {

    private lateinit var expectedDecryptedString: String

    @Test
    fun `decrypt mastercard payload successfully`() {
        when_decrypt_a_mastercard_encrypted_payload()
        then_returns_a_mastercard_decrypted_payload()
    }

    private fun when_decrypt_a_mastercard_encrypted_payload() {
        val decryptMastercardPayload = DecryptorMastercardPayload(classPathPkcs8RsaPrivateKeyLoader)
        expectedDecryptedString = decryptMastercardPayload.execute(
            encryptedBody.toJsonString(),
            keyFilePath
        )
    }

    private fun then_returns_a_mastercard_decrypted_payload() {
        Assertions.assertTrue(expectedDecryptedString.contains(aDecryptedBody["paymentAccountReference"] as String))
    }

}