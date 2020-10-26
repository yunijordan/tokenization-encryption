package action

import infrastructure.EncryptUtils.signMessage

class SignMessage {

    fun execute(message: String, privateKey: String): ByteArray? {
        return signMessage(message, privateKey)
    }

}