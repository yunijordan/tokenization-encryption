package action

import net.veritran.encryption.action.DecryptMdesPayload
import net.veritran.encryption.infrastructure.EncryptUtils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import utils.EncryptFixture.decryptedBody

import utils.EncryptFixture.encryptedBody

import java.security.Key

class DecryptMdesPayloadTest {

    private val decryptMdesPayload = DecryptMdesPayload()
    private lateinit var expectedDecryptedString: String
    private var encryptedData: String
    private var encryptedAesKey: String
    private var oaepHashingAlgorithm: String
    private var initialVector: String
    private var privateTspKey: Key

    init {
        encryptedData = encryptedBody["encryptedData"] as String
        encryptedAesKey = encryptedBody["encryptedKey"] as String
        oaepHashingAlgorithm = encryptedBody["oaepHashingAlgorithm"] as String
        initialVector = encryptedBody["iv"] as String
        privateTspKey =
            EncryptUtils.getPrivateKey("src/test/resources/digital-enablement-sandbox-decryption-key.key")
    }
    
    @Test
    fun decrypt_mdes_payload_successfully() {
        when_decrypt_a_mdes_encrypted_payload()
        then_we_have_a_decrypted_body()
    }

    private fun when_decrypt_a_mdes_encrypted_payload() {
        expectedDecryptedString =
            decryptMdesPayload.execute(
                encryptedData,
                encryptedAesKey,
                oaepHashingAlgorithm,
                initialVector,
                privateTspKey
            )
    }

    private fun then_we_have_a_decrypted_body() {
        Assertions.assertTrue(expectedDecryptedString.contains(decryptedBody["paymentAccountReference"] as String))
    }
}