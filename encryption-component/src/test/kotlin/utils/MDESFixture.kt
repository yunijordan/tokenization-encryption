package utils

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser

import net.veritran.encryption.domain.algorithm.CipherTransformations

object MDESFixture {

    const val keyFilePath = "src/test/resources/digital-enablement-sandbox-decryption-key.key"

    val encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
    val decryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject

    val aCipherTransformation = CipherTransformations.AES_CBC_PKCS5PADDING.value

}