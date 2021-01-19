package action.payload.mastercard

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercardPayload
import net.veritran.encryption.action.payload.mastercard.EncryptorMastercardPayload
import net.veritran.encryption.infrastructure.adapter.driven.classPathPkcs8RsaLoader
import net.veritran.encryption.infrastructure.adapter.driven.classPathX509Loader
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import utils.MastercardFixture.aDecryptedBody

class EncrypterMastercardPayloadTest {

    @Test
    fun encrypt_mastercard_payload_successfully() {
        val encryptMastercardPayload = EncryptorMastercardPayload(classPathX509Loader)
        val pemFilePath = "src/test/resources/certificates/test_certificate-2048.pem"
        val derFilePath = "src/test/resources/keys/test_key_pkcs8-2048.der"

        val encryptedPayload = encryptMastercardPayload.execute(
            aDecryptedBody.toJsonString(),
            pemFilePath
        )

        val decryptMastercardPayload = DecryptorMastercardPayload(classPathPkcs8RsaLoader)

        val decryptedPayload = decryptMastercardPayload.execute(
            encryptedPayload,
            derFilePath
        )

        Assertions.assertEquals(aDecryptedBody.toJsonString(), decryptedPayload)
    }

}