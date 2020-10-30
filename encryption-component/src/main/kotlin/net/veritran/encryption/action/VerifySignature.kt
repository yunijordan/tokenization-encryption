package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils.verifySign

class VerifySignature {

    fun execute(
            messageHash: ByteArray,
            aValue: String,
            publicKey: String,
            keyAlgorithm: String,
            transformation: String,
            hashAlgorithm: String
    ): Boolean {
        return verifySign(messageHash, aValue, publicKey, keyAlgorithm, transformation, hashAlgorithm)
    }
}