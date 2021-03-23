package com.veritran.encryption.infraestructure.out;

import net.veritran.encryption.action.payload.istp.DecryptorItsp;
import net.veritran.encryption.action.payload.istp.EncryptorItsp;
import net.veritran.encryption.action.payload.mastercard.DecryptorMastercard;
import net.veritran.encryption.action.payload.mastercard.EncryptorMastercard;
import net.veritran.encryption.action.payload.visa.DecryptorVisa;
import net.veritran.encryption.action.payload.visa.EncryptorVisa;
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider;
import net.veritran.encryption.port.inbound.CipherAction;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider.Factory;

@Configuration
public class CipherActionsConfig {

    @Bean
    public CipherAction mastercardDecryptor() {
        return new DecryptorMastercard(Factory
                .from(toAbsolutePath("keys/mastercard/test_key_pkcs8-2048.der"))
                .asMastercardPrivateKey());
    }

    @Bean
    public CipherAction mastercardEncryptor() {
        return new EncryptorMastercard(Factory
                .from(toAbsolutePath("keys/mastercard/test_certificate-2048.pem"))
                .asMastercardPublicKey());
    }

    @Bean
    public CipherAction visaEncryptor() {
        return new EncryptorVisa(Factory
                .from(toAbsolutePath("keys/visa/test1.pub")).asVisaPublicKey(),
                Factory.from(toAbsolutePath("keys/visa/test1.pkcs8")).asVisaSingerKey());
    }

    @Bean
    public CipherAction visaDecryptor() {
        return new DecryptorVisa(Factory
                .from(toAbsolutePath("keys/visa/test1.pkcs8")).asVisaPrivateKey(),
                Factory.from(toAbsolutePath("keys/visa/test1.pub")).asVisaVerifierKey());
    }

    @Bean
    public CipherAction itspDecryptor() {
        return new DecryptorItsp(Factory
                .from(toAbsolutePath("keys/mastercard/test_key_pkcs8-2048.der"))
                .asItspPrivateKey());
    }

    @Bean
    public CipherAction itspEncryptor() {
        return new EncryptorItsp(Factory
                .from(toAbsolutePath("keys/mastercard/test_certificate-2048.pem"))
                .asItspPublicKey());
    }

    private String toAbsolutePath(String path) {
        return this.getClass().getClassLoader()
                .getResource(path).toString()
                .replace("file:/", "")
                .replace("jar:issuer-digitization-api/issuer-digitization.jar!/", "");
    }

}
