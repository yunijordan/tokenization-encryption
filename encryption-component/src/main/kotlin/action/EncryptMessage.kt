
import infrastructure.EncryptUtils

class EncryptMessage {

    fun execute(message: String, publicKey: String): String {
        return EncryptUtils.encrypt(message, publicKey)
    }

}