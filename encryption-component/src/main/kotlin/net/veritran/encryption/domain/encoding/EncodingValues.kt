package net.veritran.encryption.domain.encoding

enum class EncodingValues(val value: String) {
    BASE64("BASE64"),
    HEX("HEX")
}

enum class HashAlgorithms(val value: String) {

    SHA_256("SHA-256");

    companion object {
        fun validate(value: String): Boolean {
            return HashAlgorithms.values().any { item -> item.value == value }
        }
    }
}



