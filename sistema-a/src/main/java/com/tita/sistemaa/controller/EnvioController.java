package com.tita.sistemaa.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tita.sistemaa.service.KmsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

/**
 * Controlador de Sistema A que recibe solicitudes del frontend,
 * cifra el payload plano invocando el KMS de Vault y lo transmite al Sistema B.
 */
@RestController
@RequestMapping("/api/a/enviar")
@RequiredArgsConstructor
public class EnvioController {

    private final KmsService kmsService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();

    @PostMapping
    public ResponseEntity<?> enviarCifrado(
            @RequestBody Map<String, Object> payload,
            @RequestHeader(value = "X-User-Rol", required = false) String rol,
            @RequestHeader(value = "X-User-Email", required = false) String usuario) {

        if (!"ADMINISTRADOR".equalsIgnoreCase(rol)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Acceso denegado. Se requiere rol de ADMINISTRADOR");
            return ResponseEntity.status(403).body(error);
        }

        try {
            // 1. Serializar el payload plano a JSON String
            String plainJson = objectMapper.writeValueAsString(payload);

            // 2. Solicitar cifrado al KMS (Vault)
            String ciphertext = kmsService.encrypt(plainJson);

            // 3. Transmitir el texto cifrado (ciphertext) a Sistema B
            String destinoUrl = "http://sistema-b:8082/api/b/recibir";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            if (usuario != null) headers.set("X-User-Email", usuario);
            if (rol != null) headers.set("X-User-Rol", rol);

            Map<String, String> requestBody = new HashMap<>();
            requestBody.put("ciphertext", ciphertext);

            HttpEntity<Map<String, String>> entity = new HttpEntity<>(requestBody, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(destinoUrl, entity, Map.class);

            // 4. Retornar el resultado de la comunicacion al cliente
            Map<String, Object> result = new HashMap<>();
            result.put("status", "Enviado de forma segura a Sistema B");
            result.put("ciphertextEnviado", ciphertext);
            result.put("respuestaSistemaB", response.getBody());

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Fallo al cifrar y enviar trama");
            error.put("mensaje", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }
}
