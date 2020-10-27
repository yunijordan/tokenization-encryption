package net.veritran.encryption

class DecryptMessage {

    fun execute(message: String, privateKeyStr: String, transformation: String, algorithm: String): String {
        return EncryptUtils.decrypt(message, privateKeyStr, transformation, algorithm)
    }

}