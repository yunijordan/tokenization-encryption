package action.jwe

import utils.MessageFixture.aHashAlgorithm
import utils.MessageFixture.aMessage
import utils.MessageFixture.aPrivateKey
import utils.MessageFixture.aPublicKey
import utils.MessageFixture.aPublicKey_2048
import utils.MessageFixture.aKeyAlgorithm
import utils.MessageFixture.aValidCipherTransformation
import utils.MessageFixture.anAlgorithmIdentifier
import utils.MessageFixture.jwePrivateKey

import net.veritran.encryption.infrastructure.JweUtils
import net.veritran.encryption.infrastructure.EncryptUtils.signMessage
import net.veritran.encryption.infrastructure.EncryptUtils.verifySign
import net.veritran.encryption.action.jwe.CreateJWE

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

import java.util.Base64

class CreateJweTest {

    private lateinit var encryptedMessage: String

    @Test
    fun encrypt_message_in_jwe_with_asymmetric_key() {
        when_we_build_a_jwe_object_with_public_key()
        then_we_have_an_asymmetric_encrypted_payload()
    }

    private fun when_we_build_a_jwe_object_with_public_key() {
        encryptedMessage = CreateJWE.execute(
            aPublicKey_2048,
            aPrivateKey,
            aMessage,
            aKeyAlgorithm,
            anAlgorithmIdentifier,
            aValidCipherTransformation,
            aHashAlgorithm
        )
    }

    private fun then_we_have_an_asymmetric_encrypted_payload() {
        val signedPayload: String = JweUtils.jwePayload(
                jwePrivateKey,
                encryptedMessage,
                anAlgorithmIdentifier
        )
        assertEquals(
            signedPayload,
            Base64.getEncoder()
                .encodeToString(signMessage(
                    aMessage,
                    aPrivateKey,
                    aKeyAlgorithm,
                    aValidCipherTransformation,
                    aHashAlgorithm)
                )
        )
        assertTrue(
            verifySign(
                Base64.getDecoder().decode(signedPayload),
                aMessage,
                aPublicKey,
                aKeyAlgorithm,
                aValidCipherTransformation,
                aHashAlgorithm
            )
        )
    }

}