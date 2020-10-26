package action

import infrastructure.EncryptUtils.sign

class Sign {

    fun execute(aValue: String, privateKey: String): ByteArray? {
        return sign(aValue, privateKey)
    }

}