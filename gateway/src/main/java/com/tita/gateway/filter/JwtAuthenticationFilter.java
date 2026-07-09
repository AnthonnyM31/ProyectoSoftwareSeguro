package com.tita.gateway.filter;

import com.tita.gateway.config.RouteValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Filtro global del Gateway que intercepta peticiones a endpoints protegidos,
 * valida el JWT firmado asimetricamente por Keycloak (RS256) y propaga el usuario y su rol.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final RouteValidator routeValidator;

    @Value("${app.keycloak.jwks-uri}")
    private String jwksUri;

    private volatile PublicKey keycloakPublicKey;

    public JwtAuthenticationFilter(RouteValidator routeValidator) {
        this.routeValidator = routeValidator;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (request.getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        if (!routeValidator.isSecured.test(request)) {
            return chain.filter(exchange);
        }

        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String authHeader = request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);
        String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;

        try {
            Claims claims = parseToken(token);
            String email = claims.get("email") != null ? String.valueOf(claims.get("email")) : claims.getSubject();
            String rol = extractRol(claims);

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Email", email)
                    .header("X-User-Rol", rol)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        } catch (Exception e) {
            System.err.println("JWT Authentication Error: " + e.getMessage());
            e.printStackTrace();
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private Claims parseToken(String token) throws Exception {
        PublicKey pubKey = getKeycloakPublicKey();
        return Jwts.parser()
                .verifyWith(pubKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private String extractRol(Claims claims) {
        if (claims.containsKey("realm_access")) {
            Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
            if (realmAccess.containsKey("roles")) {
                List<String> roles = (List<String>) realmAccess.get("roles");
                if (roles.contains("ADMINISTRADOR")) return "ADMINISTRADOR";
                if (roles.contains("BODEGUERO")) return "BODEGUERO";
                if (roles.contains("CHOFER")) return "CHOFER";
            }
        }
        return "USUARIO";
    }

    private PublicKey getKeycloakPublicKey() throws Exception {
        if (this.keycloakPublicKey == null) {
            synchronized (this) {
                if (this.keycloakPublicKey == null) {
                    this.keycloakPublicKey = fetchPublicKeyFromJwks(jwksUri);
                }
            }
        }
        return this.keycloakPublicKey;
    }

    private PublicKey fetchPublicKeyFromJwks(String uri) throws Exception {
        java.net.http.HttpClient client = java.net.http.HttpClient.newHttpClient();
        java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create(uri))
                .GET()
                .build();
        java.net.http.HttpResponse<String> resp = client.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new RuntimeException("Fallo al obtener JWKS, status: " + resp.statusCode());
        }
        String body = resp.body();

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(body);
        JsonNode keys = root.get("keys");
        String n = null;
        String e = null;

        if (keys != null && keys.isArray()) {
            for (JsonNode key : keys) {
                JsonNode use = key.get("use");
                if (use != null && "sig".equals(use.asText())) {
                    n = key.get("n").asText();
                    e = key.get("e").asText();
                    break;
                }
            }
        }

        if (n == null || e == null) {
            throw new RuntimeException("No se encontro exponente o modulo RSA de firma (use: sig) en el JWKS");
        }

        byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(e);
        java.math.BigInteger modulus = new java.math.BigInteger(1, modulusBytes);
        java.math.BigInteger exponent = new java.math.BigInteger(1, exponentBytes);
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(spec);
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
