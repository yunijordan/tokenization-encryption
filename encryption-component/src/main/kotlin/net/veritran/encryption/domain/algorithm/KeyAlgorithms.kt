package net.veritran.encryption.domain.algorithm

enum class KeyAlgorithms(val value: String) {
    RSA("RSA"),
    AES("AES");

    companion object {
        fun validate(value: String): Boolean {
            return values().any { item -> item.value == value }
        }
    }
}
