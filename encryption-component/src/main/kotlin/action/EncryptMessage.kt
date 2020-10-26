
import infrastructure.EncryptUtils

class EncryptMessage {

    fun execute(aValue: String, publicKeyStr: String): String {
        return EncryptUtils.encrypt(aValue, publicKeyStr)
    }

}