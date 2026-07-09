package com.tita.gateway.config;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

/**
 * Validador de rutas que determina cuales endpoints estan exentos de
 * la verificacion del token JWT de Keycloak (como recursos estaticos del frontend).
 */
@Component
public class RouteValidator {

    public static final List<String> OPEN_API_ENDPOINTS = List.of(
            "/realms",
            "/resources",
            "/actuator",
            "/index.html",
            "/style.css",
            "/app.js",
            "/js/"
    );

    public final Predicate<ServerHttpRequest> isSecured = request -> {
        String path = request.getURI().getPath();
        // Permitir el acceso a la pagina principal de control
        if ("/".equals(path) || path.isEmpty()) {
            return false;
        }
        return OPEN_API_ENDPOINTS.stream().noneMatch(path::contains);
    };
}
