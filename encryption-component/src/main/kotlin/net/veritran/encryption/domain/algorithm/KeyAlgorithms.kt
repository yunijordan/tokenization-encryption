package net.veritran.encryption.domain.algorithm

enum class KeyAlgorithms(val value: String) {
    RSA("RSA");

    companion object {
        fun validate(algorithm: String): Boolean {
            return values().any { keyAlgorithm -> keyAlgorithm.value == algorithm }
        }
    }
}
