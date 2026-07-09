package com.tita.sistemab.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tita.sistemab.service.KmsService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controlador de Sistema B que recibe las tramas cifradas desde Sistema A,
 * invoca el KMS de Vault para descifrarlas y retorna el JSON plano.
 */
@RestController
@RequestMapping("/api/b/recibir")
@RequiredArgsConstructor
public class RecepcionController {

    private final KmsService kmsService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @PostMapping
    public ResponseEntity<?> recibirCifrado(
            @RequestBody Map<String, String> request,
            @RequestHeader(value = "X-User-Rol", required = false) String rol,
            @RequestHeader(value = "X-User-Email", required = false) String usuario) {

        if (!"ADMINISTRADOR".equalsIgnoreCase(rol) && !"BODEGUERO".equalsIgnoreCase(rol)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Acceso denegado. Se requiere rol de ADMINISTRADOR o BODEGUERO");
            return ResponseEntity.status(403).body(error);
        }

        try {
            String ciphertext = request.get("ciphertext");
            if (ciphertext == null) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "Falta el parametro ciphertext");
                return ResponseEntity.badRequest().body(error);
            }

            // 1. Descifrar usando KMS (Vault)
            String plainJson = kmsService.decrypt(ciphertext);

            // 2. Parsear el JSON plano resultante a objeto Map
            Map<String, Object> payload = objectMapper.readValue(plainJson, Map.class);

            // 3. Retornar el resultado descifrado
            Map<String, Object> response = new HashMap<>();
            response.put("status", "Trama recibida y descifrada exitosamente en Sistema B");
            response.put("payloadDescifrado", payload);
            response.put("auditUser", usuario);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Error al descifrar la trama en Sistema B");
            error.put("mensaje", e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }
}
