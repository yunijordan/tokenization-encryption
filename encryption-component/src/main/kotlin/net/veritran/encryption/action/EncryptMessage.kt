package net.veritran.encryption.action

import net.veritran.encryption.domain.algorithm.CipherTransformations
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.domain.error.DomainError
import net.veritran.encryption.infrastructure.EncryptUtils
object EncryptMessage {

    fun execute(
        message: String,
        publicKey: String,
        cipherTransformation: String,
        keyAlgorithm: String
    ): String {
        validateKeyAlgorithm(keyAlgorithm)
        validateCipherTransformation(cipherTransformation)
        return EncryptUtils.encrypt(message, publicKey, cipherTransformation, keyAlgorithm)
    }

    private fun validateKeyAlgorithm(value: String){
        if (!KeyAlgorithms.validate(value))
            throw DomainError("Invalid algorithm")
    }

    private fun validateCipherTransformation(value: String) {
        if(!CipherTransformations.validate(value))
            throw DomainError("Invalid transformation")
    }

}

