package com.veritran.encryption.actions;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.veritran.encryption.port.inbound.CipherAction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import java.util.Map;

import static java.util.Optional.of;

@Component
public class CipherConsumer {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<String, CipherAction> cipherStrategies;

    @Autowired
    public CipherConsumer(Map<String, CipherAction> encryptionStrategies) {
        this.cipherStrategies = encryptionStrategies;
    }

    public Object consume(final String name, final String value) {
        return of(value)
                .map(cipherStrategies.get(name)::execute)
                .map(r -> readAsMap(r))
                .orElseThrow(IllegalArgumentException::new);
    }

    private Object readAsMap(String r) {
        try {
            return mapper.readValue(r, Map.class);
        } catch (JsonProcessingException e) {
            return r;
        }
    }

    private Object validateFromJsonString(String json) {
        if (isValidJSON(json)) {
            try {
                return mapper.convertValue(json, Map.class);
            } catch (Exception e) {
                throw new IllegalArgumentException("unable to parse json " + json);
            }
        }else {
            return json;
        }
    }

    public boolean isValidJSON(final String json) {
        try {
            mapper.convertValue(json, Map.class);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}
