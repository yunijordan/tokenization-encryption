package action.payload.mastercard

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercardPayload
import net.veritran.encryption.action.payload.mastercard.EncrypterMastercardPayload
import net.veritran.encryption.domain.encoding.classPathPkcs8RsaKeyFinder
import net.veritran.encryption.domain.encoding.classPathX509CertificateFinder
import net.veritran.encryption.infrastructure.hexEncode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import utils.MastercardFixture.aDecryptedBody

class EncrypterMastercardPayloadTest {

    @Test
    fun encrypt_mastercard_payload_successfully() {
        val encryptMastercardPayload = EncrypterMastercardPayload(
            aDecryptedBody.toJsonString(),
            classPathX509CertificateFinder
        )
        val pemFilePath = "src/test/resources/certificates/test_certificate-2048.pem"
        val derFilePath = "src/test/resources/keys/test_key_pkcs8-2048.der"

        val encryptedPayload = encryptMastercardPayload.execute(pemFilePath)

        val decryptMastercardPayload = DecryptorMastercardPayload(classPathPkcs8RsaKeyFinder)

        val decryptedPayload = decryptMastercardPayload.execute(
            encryptedPayload,
            encryptMastercardPayload.encryptedKey,
            encryptMastercardPayload.vector.hexEncode(),
            derFilePath
        )

        Assertions.assertEquals(aDecryptedBody.toJsonString(), decryptedPayload)
    }

}