package action.payload.mastercard

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercardPayload
import net.veritran.encryption.domain.encoding.classPathPkcs8RsaKeyFinder
import net.veritran.encryption.infrastructure.EncryptUtils.getPrivateKey
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import utils.MastercardFixture.aDecryptedBody
import utils.MastercardFixture.encryptedBody
import utils.MastercardFixture.keyFilePath
import java.security.Key

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DecryptorMastercardPayloadTest {

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
    fun `decrypt mastercard payload successfully`() {
        when_decrypt_a_mastercard_encrypted_payload()
        then_returns_a_mastercard_decrypted_payload()
    }

    private fun when_decrypt_a_mastercard_encrypted_payload() {
        val decryptMastercardPayload = DecryptorMastercardPayload(classPathPkcs8RsaKeyFinder)
        expectedDecryptedString = decryptMastercardPayload.execute(
            anEncryptedData,
            anEncryptedKey,
            anInitialVector,
            keyFilePath
        )
    }

    private fun then_returns_a_mastercard_decrypted_payload() {
        Assertions.assertTrue(expectedDecryptedString.contains(aDecryptedBody["paymentAccountReference"] as String))
    }

}