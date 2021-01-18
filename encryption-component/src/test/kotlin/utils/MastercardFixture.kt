package utils

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser

object MastercardFixture {

    const val keyFilePath = "src/test/resources/digital-enablement-sandbox-decryption-key.key"

    val encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
    val aDecryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject

}