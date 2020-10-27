package net.veritran.encryption

import net.veritran.encryption.EncryptUtils.verifySign

class VerifySignature {

    fun execute(
        messageHash: ByteArray,
        aValue: String,
        publicKey: String,
        algorithm: String,
        transformation: String,
        hashAlgorithm: String
    ): Boolean {
        return verifySign(messageHash, aValue, publicKey, algorithm, transformation, hashAlgorithm)
    }
}