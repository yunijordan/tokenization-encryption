
import infrastructure.EncryptUtils

class EncryptMessage {

    fun execute(message: String, publicKey: String, transformation: String): String {
        return EncryptUtils.encrypt(message, publicKey, transformation)
    }

}