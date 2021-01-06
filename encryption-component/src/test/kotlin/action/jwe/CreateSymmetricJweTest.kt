package action.jwe

import utils.MessageFixture.aMessage
import utils.MessageFixture.aSymmetricKey
import utils.MessageFixture.symmetricKey
import net.veritran.encryption.infrastructure.JweUtils.jwePayload
import net.veritran.encryption.action.jwe.CreateSymmetricJWE
import net.veritran.encryption.domain.algorithm.AlgorithmIdentifiers
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
            aSymmetricKey,
            aMessage,
            AlgorithmIdentifiers.A128KW.value
        )
    }

    private fun then_we_have_an_encrypted_payload() {
        Assertions.assertEquals(
            jwePayload(symmetricKey, encryptedMessage!!, AlgorithmIdentifiers.A128KW.value),
            aMessage
        )
    }
}