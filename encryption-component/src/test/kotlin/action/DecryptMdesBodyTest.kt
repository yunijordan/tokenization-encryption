package action

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import net.veritran.encryption.action.DecryptMdesMessage
import net.veritran.encryption.infrastructure.EncryptUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.security.Key

class DecryptMdesBodyTest {

    private val decryptMdesMessage = DecryptMdesMessage()
    private lateinit var encryptedBody: JsonObject
    private lateinit var decryptedBody: JsonObject
    private lateinit var expectedDecryptedString: String
    private lateinit var encryptedData: String
    private lateinit var encryptedAesKey: String
    private lateinit var oaepHashingAlgorithm: String
    private lateinit var initialVector: String
    private lateinit var privateVeritranKey: Key

    @Test
    fun decrypt_aes_successfully() {
        given_an_encrypted_body()
        when_decrypt_using_our_key_and_embedded_key()
        then_we_have_a_decrypted_body()
    }

    private fun given_an_encrypted_body() {
        encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
        decryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject
        encryptedData = encryptedBody["encryptedData"] as String
        encryptedAesKey = encryptedBody["encryptedKey"] as String
        oaepHashingAlgorithm = encryptedBody["oaepHashingAlgorithm"] as String
        initialVector = encryptedBody["iv"] as String
        privateVeritranKey =
                EncryptUtils.getPrivateKey("src/test/resources/digital-enablement-sandbox-decryption-key.key")
    }

    private fun when_decrypt_using_our_key_and_embedded_key() {
        expectedDecryptedString =
            decryptMdesMessage.execute(
                encryptedData,
                encryptedAesKey,
                oaepHashingAlgorithm,
                initialVector,
                privateVeritranKey
            )
    }

    private fun then_we_have_a_decrypted_body() {
        Assertions.assertTrue(expectedDecryptedString.contains(decryptedBody["paymentAccountReference"] as String))
    }
}