package action

import action.EncryptFixture.aMessage
import action.EncryptFixture.aPrivateKey
import action.EncryptFixture.aPublicKey
import action.EncryptFixture.aPublicKey_2048
import action.EncryptFixture.jwePrivateKey

import infrastructure.JweUtils
import infrastructure.EncryptUtils.signMessage
import infrastructure.EncryptUtils.verifySign

import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

import java.util.Base64

class CreateJweTest {

    private lateinit var encryptedMessage: String
    private val createJWE = CreateJWE()

    @Test
    fun encrypt_message_in_jwe_with_asymmetric_key() {
        when_we_build_a_jwe_object_with_public_key()
        then_we_have_an_asymmetric_encrypted_payload()
    }

    private fun when_we_build_a_jwe_object_with_public_key() {
        encryptedMessage = createJWE.execute(
            aPublicKey_2048,
            aPrivateKey,
            aMessage,
            KeyManagementAlgorithmIdentifiers.RSA_OAEP_256
        )
    }

    private fun then_we_have_an_asymmetric_encrypted_payload() {
        val signedPayload: String =
            JweUtils.jwePayload(jwePrivateKey, encryptedMessage, KeyManagementAlgorithmIdentifiers.RSA_OAEP_256)
        assertEquals(
            signedPayload,
            Base64.getEncoder().encodeToString(signMessage(aMessage, aPrivateKey))
        )
        assertTrue(
            verifySign(
                Base64.getDecoder().decode(signedPayload),
                aMessage,
                aPublicKey
            )
        )
    }

}