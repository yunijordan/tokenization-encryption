package com.veritran.encryption;


import com.veritran.encryption.actions.CipherConsumer;
import net.veritran.encryption.port.inbound.CipherAction;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CipherConsumerTest {


    @Test
    public final void decryptMessage() {

        String expected = "expected";
        String decrypted = "expected";
        String strategyId = "id";
        String messageToDecrypt = "message";
        HashMap<String, CipherAction> encryptionStrategies = new HashMap<>();
        CipherAction cipherAction = mock(CipherAction.class);
        when(cipherAction.execute(messageToDecrypt)).thenReturn(decrypted);

        encryptionStrategies.put("id", cipherAction);

        CipherConsumer cipherConsumer = new CipherConsumer(encryptionStrategies);

        Object result = cipherConsumer.consume(strategyId, messageToDecrypt);

        assertEquals(expected, result);

    }

}
