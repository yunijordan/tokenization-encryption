package action

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import net.veritran.encryption.action.DecryptMdesMessage
import net.veritran.encryption.infrastructure.EncryptUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import java.security.Key

class DecryptMdesBodyTest {

    private val decryptMdesMessage = DecryptMdesMessage()
    private lateinit var encryptedBody: JsonObject
    private lateinit var decryptedBody: JsonObject
    private lateinit var aesEncryptedKey: String
    private lateinit var expectedDecryptedString: String
    private lateinit var encryptedData: String;
    private lateinit var encryptedAesKey: String;
    private lateinit var oaepHashingAlgorithm: String;
    private lateinit var initialVector: String;
    private lateinit var privateVeritranKey: Key;

    private fun given_an_ecrypted_mdes_json() {
        encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
        decryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject

        encryptedData = encryptedBody.get("encryptedData") as String
        encryptedAesKey = encryptedBody.get("encryptedKey") as String
        oaepHashingAlgorithm = encryptedBody.get("oaepHashingAlgorithm") as String
        initialVector = encryptedBody.get("iv") as String
        privateVeritranKey =
            EncryptUtils.getPrivateKey("src/test/resources/digital-enablement-sandbox-decryption-key.key")
    }

    @Test
    fun decrypt_aes_successfully() {
        given_an_ecrypted_mdes_json()
        when_decrypt_using_our_key_and_embebed_key()
        then_we_have_a_decrypted_body()
    }

    private fun when_decrypt_using_our_key_and_embebed_key() {
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
        Assertions.assertTrue(expectedDecryptedString.contains(decryptedBody.get("paymentAccountReference") as String))
    }
}