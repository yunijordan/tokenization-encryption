package net.veritran.encryption

class EncryptMessage {

    fun execute(message: String, publicKey: String, transformation: String, algorithm: String): String {
        return EncryptUtils.encrypt(message, publicKey, transformation, algorithm)
    }

}