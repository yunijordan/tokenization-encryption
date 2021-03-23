package com.veritran.encryption.infraestructure.adapater.in;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.veritran.encryption.actions.CipherConsumer;
import com.veritran.encryption.domain.Payload;
import io.swagger.annotations.ApiParam;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
public class CipherController {

    private final ObjectMapper mapper = new ObjectMapper();
    private final CipherConsumer cipherConsumer;

    public CipherController(final CipherConsumer cipherConsumer) {
        this.cipherConsumer = cipherConsumer;
    }

    @GetMapping("check")
    public String get() {
        return "OK";
    }

    @PostMapping("decrypt/{from}")
    public ResponseEntity<Payload> decrypt(@ApiParam(allowableValues = "itsp,visa,mastercard")
                                           @PathVariable final String from,
                                           final @RequestBody Payload encrypted) throws JsonProcessingException {
        String value;
        if (encrypted.getPayload() instanceof String) {
            value = encrypted.getPayload().toString();
        } else {
            value = mapper.writeValueAsString(encrypted.getPayload());
        }
        Object decrypted = cipherConsumer.consume(from + "Decryptor", value);
        Payload payload = new Payload(decrypted);
        return ResponseEntity.ok()
                .headers(h -> h.add(HttpHeaders.CONTENT_TYPE, "application/json"))
                .body(payload);
    }


    @PostMapping("encrypt/{from}")
    public ResponseEntity<Payload> encrypt(@ApiParam(allowableValues = "itsp,visa,mastercard")
                                           @PathVariable String from,
                                           final @NonNull @RequestBody Payload decrypted) throws JsonProcessingException {
        String value = mapper.writeValueAsString(decrypted.getPayload());
        Payload payload = Optional.of(value)
                .map(msg -> cipherConsumer.consume(from + "Encryptor", msg))
                .map(Payload::new).orElseThrow(IllegalArgumentException::new);
        return ResponseEntity.ok()
                .headers(h -> h.add(HttpHeaders.CONTENT_TYPE, "application/json"))
                .body(payload);
    }

}
