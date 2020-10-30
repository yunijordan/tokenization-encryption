package net.veritran.encryption.action

import net.veritran.encryption.domain.error.InvalidAlgorithm
import net.veritran.encryption.infrastructure.EncryptUtils

object EncryptMessage {

    fun execute(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        if (validateKeyAlgorithm(keyAlgorithm))
            return EncryptUtils.encrypt(message, publicKey, cipherTransformation, keyAlgorithm)
        throw InvalidAlgorithm("Invalid algorithm")
    }

    private fun validateKeyAlgorithm(keyAlgorithm: String) = keyAlgorithm == "RSA"

}