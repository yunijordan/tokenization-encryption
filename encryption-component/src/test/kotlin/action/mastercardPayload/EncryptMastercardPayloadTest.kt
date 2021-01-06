package action.mastercardPayload

import net.veritran.encryption.action.mastercardPayload.DecryptMastercardPayload
import net.veritran.encryption.action.mastercardPayload.EncryptMastercardPayload
import net.veritran.encryption.domain.algorithm.HashAlgorithms
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.hexEncode

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import utils.MastercardFixture.aCipherTransformation
import utils.MastercardFixture.aDecryptedBody
import utils.MastercardFixture.aKey
import utils.MastercardFixture.aTSPKey

class EncryptMastercardPayloadTest {

    private val decryptMastercardPayload = DecryptMastercardPayload()

    @Test
    fun encrypt_mastercard_payload_successfully() {
        val encryptMastercardPayload = EncryptMastercardPayload(aDecryptedBody.toJsonString(), aKey, aTSPKey)
        val encryptedPayload = encryptMastercardPayload.execute()
        val decryptedPayload = decryptMastercardPayload.execute(
                encryptedPayload,
                aKey,
                HashAlgorithms.SHA_256.value,
                encryptMastercardPayload.vector.hexEncode(),
                aCipherTransformation,
                EncryptUtils.getPrivateKey(aTSPKey, KeyAlgorithms.RSA.value)
        )
        Assertions.assertEquals(aDecryptedBody.toJsonString(), decryptedPayload)
    }

}