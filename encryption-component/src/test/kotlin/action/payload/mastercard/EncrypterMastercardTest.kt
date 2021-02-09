package action.payload.mastercard

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercard
import net.veritran.encryption.action.payload.mastercard.EncryptorMastercard
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import utils.MastercardFixture.aDecryptedBody

class EncrypterMastercardTest {

    @Test
    fun encrypt_mastercard_payload_successfully() {
        val publicKeyFilePath = "src/test/resources/certificates/test_certificate-2048.pem"
        val privateKeyFilePath = "src/test/resources/keys/test_key_pkcs8-2048.der"
        val encryptMastercardPayload = EncryptorMastercard(
            ClassPathKeyLoaderProvider.from(publicKeyFilePath).asMastercardPublicKey()
        )

        val encryptedPayload = encryptMastercardPayload.execute(
            aDecryptedBody.toJsonString()
        )

        val decryptMastercardPayload = DecryptorMastercard(
            ClassPathKeyLoaderProvider.from(privateKeyFilePath).asMastercardPrivateKey()
        )

        val decryptedPayload = decryptMastercardPayload.execute(
            encryptedPayload
        )

        Assertions.assertEquals(aDecryptedBody.toJsonString(), decryptedPayload)
    }

}