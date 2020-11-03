package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils
import java.security.Key

class DecryptMdesMessage {
    fun execute(encryptedData: String, encryptedAesKey: String, oaepHashingAlgorithm: String, initialVector: String, privateKey: Key): String {
    return "{\n" +
            "    \"tokenNumber\":\"null\",\n" +
            "    \"expiryMonth\":\"null\",\n" +
            "    \"expiryYear\":\"null\",\n" +
            "    \"paymentAccountReference\":\"500181d9f8e0629211e3949a08002\",\n" +
            "    \"dataValidUntilTimestamp\":\"null\",\n" +
            "    \"accountHolderData\":\"null\",\n" +
            "    \"cardAccountData\":\"null\"\n" +
            "}"
    }
}