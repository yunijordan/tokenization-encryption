package net.veritran.encryption

import net.veritran.encryption.action.EncryptMessage

class Provider(private var encryptMessageAction: EncryptMessage = EncryptMessage()) {
    fun encryptMessage(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ) {
        encryptMessageAction.execute(message, publicKey, cipherTransformation, keyAlgorithm)
    }
}