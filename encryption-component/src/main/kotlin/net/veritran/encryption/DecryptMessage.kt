package net.veritran.encryption

class DecryptMessage {

    fun execute(message: String,
                privateKeyStr: String,
                cipherTransformation: String,
                keyAlgorithm: String): String {
        return EncryptUtils.decrypt(message, privateKeyStr, cipherTransformation, keyAlgorithm)
    }

}