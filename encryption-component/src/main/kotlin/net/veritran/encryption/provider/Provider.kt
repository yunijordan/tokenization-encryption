package net.veritran.encryption.provider

import net.veritran.encryption.action.EncryptMessage

class Provider() {
    fun encryptMessage(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ) {
        EncryptMessage.execute(message, publicKey, cipherTransformation, keyAlgorithm)
    }
}