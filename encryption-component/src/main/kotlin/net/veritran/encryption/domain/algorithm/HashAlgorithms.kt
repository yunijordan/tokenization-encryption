package net.veritran.encryption.domain.algorithm

enum class HashAlgorithms(val value: String) {

    SHA_256("SHA-256");

    companion object {
        fun validate(value: String): Boolean {
            return values().any { item -> item.value == value }
        }
    }

}
