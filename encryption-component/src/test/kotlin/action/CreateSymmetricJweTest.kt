package action

import action.EncryptFixture.aMessage
import action.EncryptFixture.asymmetricKey
import action.EncryptFixture.symmetricKey
import infrastructure.JweUtils.jwePayload
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class CreateSymmetricJweTest {
    var encryptedMessage: String? = null
    var createSymmetricJWE = CreateSymmetricJWE()
    @Test
    fun encrypt_message_in_jwe_with_symmetric_key() {
        when_we_build_a_jwe_object()
        then_we_have_an_encrypted_payload()
    }

    private fun when_we_build_a_jwe_object() {
        encryptedMessage = createSymmetricJWE.execute(
            asymmetricKey,
            aMessage,
            KeyManagementAlgorithmIdentifiers.A128KW
        )
    }

    private fun then_we_have_an_encrypted_payload() {
        Assertions.assertEquals(
            jwePayload(symmetricKey, encryptedMessage!!, KeyManagementAlgorithmIdentifiers.A128KW),
            aMessage
        )
    }
}