package action

import net.veritran.encryption.action.DecryptMDESPayload
import net.veritran.encryption.infrastructure.EncryptUtils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import utils.MDESFixture.aCipherTransformation
import utils.MDESFixture.decryptedBody
import utils.MDESFixture.encryptedBody
import utils.MDESFixture.keyFilePath

import java.security.Key

class DecryptMDESPayloadTest {

    private val decryptMDESPayload = DecryptMDESPayload()
    private lateinit var expectedDecryptedString: String
    private var encryptedData: String
    private var encryptedKey: String
    private var oaepHashingAlgorithm: String
    private var initialVector: String
    private var privateTspKey: Key

    init {
        encryptedData = encryptedBody["encryptedData"] as String
        encryptedKey = encryptedBody["encryptedKey"] as String
        oaepHashingAlgorithm = encryptedBody["oaepHashingAlgorithm"] as String
        initialVector = encryptedBody["iv"] as String
        privateTspKey = EncryptUtils.getPrivateKey(keyFilePath)
    }
    
    @Test
    fun decrypt_MDES_payload_successfully() {
        when_decrypt_a_MDES_encrypted_payload()
        then_returns_a_MDES_decrypted_payload()
    }

    private fun when_decrypt_a_MDES_encrypted_payload() {
        expectedDecryptedString =
            decryptMDESPayload.execute(
                encryptedData,
                encryptedKey,
                oaepHashingAlgorithm,
                initialVector,
                aCipherTransformation,
                privateTspKey
            )
    }

    private fun then_returns_a_MDES_decrypted_payload() {
        Assertions.assertTrue(expectedDecryptedString.contains(decryptedBody["paymentAccountReference"] as String))
    }

}