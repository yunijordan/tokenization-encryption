package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils

object EncryptMessage {

    fun execute(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        return EncryptUtils.encrypt(message, publicKey, cipherTransformation, keyAlgorithm)
    }

}