package action

import net.veritran.encryption.action.EncryptMDESPayload
import org.junit.jupiter.api.Assertions

import org.junit.jupiter.api.Test

import utils.MDESFixture.aDecryptedBody
import utils.MDESFixture.aKey
import utils.MDESFixture.aTSPKey
import java.security.GeneralSecurityException

import javax.crypto.KeyGenerator

import javax.crypto.SecretKey

class EncryptMDESPayloadTest {

    @Test
    fun encrypt_mastercard_payload_successfully() {
        val expectedEncryptedString = ""
        val encryptMDESPayload = EncryptMDESPayload(aDecryptedBody.toJsonString(), aKey, aTSPKey)

        val encryptedPayload = encryptMDESPayload.execute()

        Assertions.assertEquals(expectedEncryptedString, encryptedPayload)
    }

}