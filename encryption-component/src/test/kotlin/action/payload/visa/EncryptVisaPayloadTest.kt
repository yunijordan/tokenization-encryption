package action.payload.visa

import net.veritran.encryption.action.payload.visa.EncryptVisaPayload

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import utils.VisaFixture.aDecryptedPayload
import utils.VisaFixture.aEncryptionPublicKey
import utils.VisaFixture.aJweHeader
import utils.VisaFixture.aJwsHeader
import utils.VisaFixture.aSignaturePrivateKey
import utils.VisaFixture.encryptedJwsExpected

class EncryptVisaPayloadTest {

    private lateinit var encryptedJws: String
    private var encryptVisaPayload = EncryptVisaPayload()

    @Test
    fun `Encrypt a Visa payload successfully`() {
        when_encrypt_a_payload()
        then_returns_a_jws()
    }

    private fun when_encrypt_a_payload() {
        encryptedJws = encryptVisaPayload.execute(
                aDecryptedPayload,
                aEncryptionPublicKey,
                aSignaturePrivateKey,
                aJweHeader,
                aJwsHeader
        )
    }

    private fun then_returns_a_jws() = Assertions.assertEquals(encryptedJws, encryptedJwsExpected)

}