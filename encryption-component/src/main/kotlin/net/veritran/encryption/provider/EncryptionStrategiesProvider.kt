package net.veritran.encryption.provider

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercardPayload
import net.veritran.encryption.action.payload.mastercard.EncryptorMastercardPayload
import net.veritran.encryption.action.payload.visa.DecryptVisaPayload
import net.veritran.encryption.action.payload.visa.EncryptVisaPayload
import net.veritran.encryption.infrastructure.adapter.outbound.classPathPkcs8RsaPrivateKeyLoader
import net.veritran.encryption.infrastructure.adapter.outbound.classPathX509PublicCertLoader

class EncryptionStrategiesProvider {

    val mastercardEncryptor = EncryptorMastercardPayload(classPathX509PublicCertLoader)

    val mastercardDecryptor = DecryptorMastercardPayload(classPathPkcs8RsaPrivateKeyLoader)

    val visaEncryptor = EncryptVisaPayload()

    val visaDecryptor = DecryptVisaPayload()

}