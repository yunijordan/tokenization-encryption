package action.payload.mastercard

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercard
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import utils.MastercardFixture.aDecryptedBody
import utils.MastercardFixture.encryptedBody
import utils.MastercardFixture.keyFilePath

class DecryptorMastercardTest {

    private lateinit var expectedDecryptedString: String

    @Test
    fun `decrypt mastercard payload successfully`() {
        when_decrypt_a_mastercard_encrypted_payload()
        then_returns_a_mastercard_decrypted_payload()
    }

    private fun when_decrypt_a_mastercard_encrypted_payload() {
        val decryptMastercardPayload =
            ClassPathKeyLoaderProvider.from(keyFilePath).asMastercardPrivateKey().let(::DecryptorMastercard)
        expectedDecryptedString = decryptMastercardPayload.execute(
            encryptedBody.toJsonString()
        )
    }

    private fun then_returns_a_mastercard_decrypted_payload() {
        Assertions.assertTrue(expectedDecryptedString.contains(aDecryptedBody["paymentAccountReference"] as String))
    }

}