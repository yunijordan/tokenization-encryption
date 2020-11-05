package action

import net.veritran.encryption.action.DecryptMDESPayload
import net.veritran.encryption.infrastructure.EncryptUtils.getPrivateKey

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

import utils.MDESFixture.aCipherTransformation
import utils.MDESFixture.decryptedBody
import utils.MDESFixture.encryptedBody
import utils.MDESFixture.keyFilePath

import java.security.Key

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DecryptMDESPayloadTest {

    private val decryptMDESPayload = DecryptMDESPayload()

    private lateinit var expectedDecryptedString: String
    private lateinit var anEncryptedData: String
    private lateinit var anEncryptedKey: String
    private lateinit var aHashingAlgorithm: String
    private lateinit var anInitialVector: String
    private lateinit var aPrivateTspKey: Key

    @BeforeAll
    fun setup() {
        anEncryptedData = encryptedBody["encryptedData"] as String
        anEncryptedKey = encryptedBody["encryptedKey"] as String
        aHashingAlgorithm = encryptedBody["oaepHashingAlgorithm"] as String
        anInitialVector = encryptedBody["iv"] as String
        aPrivateTspKey = getPrivateKey(keyFilePath)
    }
    
    @Test
    fun decrypt_MDES_payload_successfully() {
        when_decrypt_a_MDES_encrypted_payload()
        then_returns_a_MDES_decrypted_payload()
    }

    private fun when_decrypt_a_MDES_encrypted_payload() {
        expectedDecryptedString = decryptMDESPayload.execute(
            anEncryptedData,
            anEncryptedKey,
            aHashingAlgorithm,
            anInitialVector,
            aCipherTransformation,
            aPrivateTspKey
        )
    }

    private fun then_returns_a_MDES_decrypted_payload() {
        Assertions.assertTrue(expectedDecryptedString.contains(decryptedBody["paymentAccountReference"] as String))
    }

}