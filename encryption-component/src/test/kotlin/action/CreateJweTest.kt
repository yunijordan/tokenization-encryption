package action

import action.EncryptFixture.aHashAlgorithm
import action.EncryptFixture.aMessage
import action.EncryptFixture.aPrivateKey
import action.EncryptFixture.aPublicKey
import action.EncryptFixture.aPublicKey_2048
import action.EncryptFixture.aTransformation
import action.EncryptFixture.aCipherAlgorithm
import action.EncryptFixture.anAlgorithmIdentifier
import action.EncryptFixture.jwePrivateKey

import net.veritran.encryption.JweUtils
import net.veritran.encryption.EncryptUtils.signMessage
import net.veritran.encryption.EncryptUtils.verifySign
import net.veritran.encryption.CreateJWE

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
            aCipherAlgorithm,
            anAlgorithmIdentifier,
            aTransformation,
            aHashAlgorithm
        )
    }

    private fun then_we_have_an_asymmetric_encrypted_payload() {
        val signedPayload: String =
            JweUtils.jwePayload(jwePrivateKey, encryptedMessage, anAlgorithmIdentifier)
        assertEquals(
            signedPayload,
            Base64.getEncoder()
                .encodeToString(signMessage(aMessage, aPrivateKey, aCipherAlgorithm, aTransformation, aHashAlgorithm))
        )
        assertTrue(
            verifySign(
                Base64.getDecoder().decode(signedPayload),
                aMessage,
                aPublicKey,
                aCipherAlgorithm,
                aTransformation,
                aHashAlgorithm
            )
        )
    }

}