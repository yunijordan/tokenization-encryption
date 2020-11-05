package action

import net.veritran.encryption.action.DecryptMDESPayload
import net.veritran.encryption.infrastructure.EncryptUtils

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import utils.MDESFixture.aCipherTransformation
import utils.MDESFixture.decryptedBody
import utils.MDESFixture.encryptedBody
import utils.MDESFixture.keyFilePath

import java.security.Key

class DecryptMDESPayloadTest {

    private val decryptMDESPayload = DecryptMDESPayload()
    private lateinit var expectedDecryptedString: String
    private var anEncryptedData: String
    private var anEncryptedKey: String
    private var aHashingAlgorithm: String
    private var anInitialVector: String
    private var aPrivateTspKey: Key

    init {
        anEncryptedData = encryptedBody["encryptedData"] as String
        anEncryptedKey = encryptedBody["encryptedKey"] as String
        aHashingAlgorithm = encryptedBody["oaepHashingAlgorithm"] as String
        anInitialVector = encryptedBody["iv"] as String
        aPrivateTspKey = EncryptUtils.getPrivateKey(keyFilePath)
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
        Assertions.assertTrue(
                expectedDecryptedString.contains(decryptedBody["paymentAccountReference"] as String)
        )
    }

}