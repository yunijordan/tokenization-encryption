package action

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import net.veritran.encryption.action.DecryptMdesPayload
import net.veritran.encryption.infrastructure.EncryptUtils
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import java.security.Key


class DecryptMdesPayloadTest {

    private val decryptMdesPayload = DecryptMdesPayload()
    private lateinit var encryptedBody: JsonObject
    private lateinit var decryptedBody: JsonObject
    private lateinit var expectedDecryptedString: String
    private lateinit var encryptedData: String
    private lateinit var encryptedAesKey: String
    private lateinit var oaepHashingAlgorithm: String
    private lateinit var initialVector: String
    private lateinit var privateTspKey: Key

    init{
        encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
        decryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject
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