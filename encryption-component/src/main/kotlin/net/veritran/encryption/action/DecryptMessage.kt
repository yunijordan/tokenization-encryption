package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils

class DecryptMessage {

    fun execute(
        message: String,
        privateKeyStr: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        return EncryptUtils.decrypt(message, privateKeyStr, cipherTransformation, keyAlgorithm)
    }

}