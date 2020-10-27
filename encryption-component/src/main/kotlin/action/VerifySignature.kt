package action

import infrastructure.EncryptUtils.verifySign

class VerifySignature {

    fun execute(
        messageHash: ByteArray,
        aValue: String,
        publicKey: String,
        algorithm: String,
        transformation: String
    ): Boolean {
        return verifySign(messageHash, aValue, publicKey, algorithm, transformation)
    }
}