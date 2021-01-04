package action

import net.veritran.encryption.action.DecryptMDESPayload
import net.veritran.encryption.action.EncryptMDESPayload
import net.veritran.encryption.domain.algorithm.HashAlgorithms
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.infrastructure.EncryptUtils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import utils.MDESFixture.aCipherTransformation
import utils.MDESFixture.aDecryptedBody
import utils.MDESFixture.aKey
import utils.MDESFixture.aTSPKey

class EncryptMDESPayloadTest {

    private val decryptMDESPayload = DecryptMDESPayload()

    @Test
    fun encrypt_mastercard_payload_successfully() {
        val encryptMDESPayload = EncryptMDESPayload(aDecryptedBody.toJsonString(), aKey, aTSPKey)
        val encryptedPayload = encryptMDESPayload.execute()
        val decryptedResult = decryptMDESPayload.execute(
                encryptedPayload,
                aKey,
                HashAlgorithms.SHA_256.value,
                encryptMDESPayload.initialVector(),
                aCipherTransformation,
                EncryptUtils.getPrivateKey(aTSPKey, KeyAlgorithms.RSA.value)
        )
        Assertions.assertEquals(aDecryptedBody.toJsonString(), decryptedResult)
    }

}