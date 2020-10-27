package net.veritran.encryption

class EncryptMessage {

    fun execute(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        return EncryptUtils.encrypt(message, publicKey, cipherTransformation, keyAlgorithm)
    }

}