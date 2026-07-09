package com.tita.sistemab.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Servicio encargado de interactuar con HashiCorp Vault (KMS) para
 * descifrar datos cifrados usando la clave guardada en el vault.
 */
@Service
public class KmsService {

    @Value("${app.vault.url:http://vault:8200}")
    private String vaultUrl;

    @Value("${app.vault.token:tita-root-token}")
    private String vaultToken;

    private final RestTemplate restTemplate = new RestTemplate();

    public String decrypt(String ciphertext) {
        try {
            String url = vaultUrl + "/v1/transit/decrypt/tita-key";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("X-Vault-Token", vaultToken);

            Map<String, String> body = new HashMap<>();
            body.put("ciphertext", ciphertext);

            HttpEntity<Map<String, String>> entity = new HttpEntity<>(body, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(url, entity, Map.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                Map<String, Object> data = (Map<String, Object>) response.getBody().get("data");
                String base64Plaintext = String.valueOf(data.get("plaintext"));
                return new String(Base64.getDecoder().decode(base64Plaintext), StandardCharsets.UTF_8);
            }
            throw new RuntimeException("Error en respuesta de Vault: " + response.getStatusCode());
        } catch (Exception e) {
            throw new RuntimeException("Error al conectar con Vault KMS para descifrar", e);
        }
    }
}
