package action

import infrastructure.EncryptUtils.signMessage

class SignMessage {

    fun execute(message: String, privateKey: String, algorithm: String, transformation: String): ByteArray? {
        return signMessage(message, privateKey, algorithm, transformation)
    }

}