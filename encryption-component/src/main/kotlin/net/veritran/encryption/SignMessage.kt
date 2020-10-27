package net.veritran.encryption

import net.veritran.encryption.EncryptUtils.signMessage

class SignMessage {

    fun execute(message: String,
                privateKey: String,
                algorithm: String,
                cipherTransformation: String,
                hashAlgorithm: String): ByteArray? {
        return signMessage(message, privateKey, algorithm, cipherTransformation, hashAlgorithm)
    }

}