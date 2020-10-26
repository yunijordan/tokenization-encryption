package action

import infrastructure.EncryptUtils

class DecryptMessage {

    fun execute(message: String, privateKeyStr: String): String {
        return EncryptUtils.decrypt(message, privateKeyStr)
    }

}