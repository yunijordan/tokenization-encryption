package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.EncryptUtils.getPrivateKey
import net.veritran.encryption.infrastructure.StringUtils.decodeBase64ToBytes

class DecryptMessage {

    fun execute(
        message: String,
        privateKeyStr: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        val messageBytes = decodeBase64ToBytes(message)
        val privateKey = getPrivateKey(privateKeyStr, keyAlgorithm)
        return EncryptUtils.decrypt(messageBytes, privateKey , cipherTransformation)
    }

}