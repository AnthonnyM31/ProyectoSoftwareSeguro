# Análisis Detallado de los Flujos de Seguridad y Roles (BODEGUERO y CHOFER)

Este documento detalla el comportamiento del sistema de transmisión segura de tramas ante las peticiones de usuarios con roles de **BODEGUERO** y **CHOFER**, analizando la interacción entre el Cliente Web, API Gateway, Sistema A (Cifrado), Sistema B (Descifrado) y HashiCorp Vault KMS.

---

## 1. Flujo Paso a Paso para el Rol BODEGUERO (Envío desde el Portal)

A continuación se detalla la secuencia cronológica de archivos y líneas de código que se ejecutan cuando un usuario con el rol `BODEGUERO` inicia sesión e intenta enviar un mensaje por el portal web:

### Paso 1: Autenticación en el Navegador e Inicialización
1. **app.js (líneas 12-15)**: La aplicación web inicializa el adaptador de Keycloak `keycloak.init({ onLoad: "login-required" })`. El usuario es redirigido a la página de login de Keycloak si no tiene una sesión activa.
2. **Autenticación (Keycloak + LDAP)**: El usuario ingresa las credenciales del Bodeguero (`bodeguero` / contraseña). Keycloak valida las credenciales contra el directorio de **OpenLDAP** y procesa el MFA (TOTP). Keycloak emite un token JWT firmado asimétricamente (RS256).
3. **app.js (líneas 43-62)**: De vuelta en la aplicación, se ejecuta `setupAuthenticatedSession()`. El JS extrae los datos del token y determina el rol activo del usuario leyendo `realm_access.roles`. Para este caso, detecta que posee el rol `"BODEGUERO"` (línea 55) y actualiza la interfaz mostrando los datos del perfil y el token JWT en el panel.

### Paso 2: Disparador del Envío desde la Interfaz
1. **app.js (líneas 71-82)**: El usuario rellena los campos del formulario de datos del pedido y presiona el botón "Enviar Seguro (KMS Cifrado)". Se dispara la función `sendSecureMessage()` y se estructura el objeto JSON plano (`pedidoId`, `materia`, `cantidad`, etc.).
2. **app.js (líneas 95-102)**: Se realiza un `fetch` hacia `/api/a/enviar` (método `POST`), pasando el JSON plano en el cuerpo y el token del Bodeguero en la cabecera `Authorization: Bearer <token_jwt>`.

### Paso 3: Intercepción en el API Gateway
1. La petición llega al puerto `8080` del Gateway y es procesada por `JwtAuthenticationFilter.java` (línea 46).
2. **JwtAuthenticationFilter.java (línea 53)**: Evalúa si la ruta requiere seguridad. La clase `RouteValidator` confirma que `/api/a/enviar` es una ruta segura (devuelve `true`).
3. **JwtAuthenticationFilter.java (líneas 57-62)**: Se valida la existencia del encabezado `Authorization`, y se extrae el string del token JWT.
4. **JwtAuthenticationFilter.java (línea 65)**: Llama a `parseToken(token)` el cual utiliza la firma pública JWKS (obtenida dinámicamente de Keycloak en las líneas 115-155) para verificar la validez e integridad del JWT.
5. **JwtAuthenticationFilter.java (línea 67)**: Invoca a `extractRol(claims)` (líneas 91-102). El token contiene `"BODEGUERO"` en sus roles del Realm, por lo que el método retorna el String `"BODEGUERO"` (línea 97).
6. **JwtAuthenticationFilter.java (líneas 69-72)**: Se muta la petición entrante agregando los encabezados internos:
   - `X-User-Email` con el correo electrónico extraído del claim.
   - `X-User-Rol` con el valor `"BODEGUERO"`.
7. **JwtAuthenticationFilter.java (línea 74)**: Se reenvía la petición mutada hacia el microservicio de destino enrutado (`http://sistema-a:8081`).

### Paso 4: Autorización en el Sistema A
1. La petición ingresa a `sistema-a:8081` y es capturada en `EnvioController.java` (línea 34) en el método `enviarCifrado(...)`.
2. Las anotaciones `@RequestHeader` mapean los encabezados inyectados por el Gateway a las variables `rol` (recibe `"BODEGUERO"`) y `usuario` (recibe el correo).
3. **EnvioController.java (líneas 39-43) (PUNTO DE CORTE)**:
   ```java
   if (!"ADMINISTRADOR".equalsIgnoreCase(rol)) {
       Map<String, String> error = new HashMap<>();
       error.put("error", "Acceso denegado. Se requiere rol de ADMINISTRADOR");
       return ResponseEntity.status(403).body(error);
   }
   ```
   Como el valor de `rol` es `"BODEGUERO"`, la expresión `!"ADMINISTRADOR".equalsIgnoreCase(rol)` resulta en `true`.
4. El controlador detiene el flujo inmediatamente, **omitiendo la llamada a Vault KMS y al Sistema B**, y retorna una respuesta HTTP `403 Forbidden` con el JSON de error.
5. **app.js (líneas 104-110)**: El navegador recibe el status 403, lanza un error con el mensaje de error parseado (`"Acceso denegado. Se requiere rol de ADMINISTRADOR"`) y lo muestra en rojo en la pantalla de depuración del portal.

---

## 2. Comportamiento del Sistema B ante Petición Directa (Bypass de API Gateway)

Si un usuario con el rol **BODEGUERO** decide eludir los controles del Gateway y del Sistema A, y envía una petición directamente al endpoint de recepción del Sistema B (`http://sistema-b:8082/api/b/recibir`) pasando una trama cifrada (ciphertext), el comportamiento dependerá del método de obtención/forjado de cabeceras:

* **Escenario A: Invocación Directa sin Cabeceras de Identidad (`X-User-*` ausentes)**:
  - Si realiza la petición directa usando herramientas de red sin suministrar cabeceras internas.
  - Al llegar a `RecepcionController.java` (línea 34):
    El parámetro `rol` es `null`.
    La evaluación: `!"ADMINISTRADOR".equalsIgnoreCase(rol) && !"BODEGUERO".equalsIgnoreCase(rol)` se convierte en `true && true = true`.
    **Resultado**: Retorna inmediatamente un error **`403 Forbidden`** (Acceso denegado). El descifrado en Vault no se ejecuta.

* **Escenario B: Invocación Directa forjando Cabeceras (`Header Spoofing`)**:
  - Si el Bodeguero añade manualmente las cabeceras HTTP internas:
    `X-User-Rol: BODEGUERO`
    `X-User-Email: bodeguero@dominio.com`
    Y adjunta una trama cifrada válida en el body JSON.
  - Al llegar a `RecepcionController.java` (línea 34):
    La evaluación de seguridad es `false` (ya que posee el rol permitido `"BODEGUERO"`).
    **Resultado**: El Sistema B descifra la trama con Vault KMS exitosamente (`200 OK`) y devuelve el JSON en texto claro.

### Análisis del Riesgo y Falla de "Confianza Ciega"
* **Vulnerabilidad**: Este comportamiento demuestra un riesgo de seguridad si los puertos de los microservicios internos (`8081` y `8082`) se exponen al exterior de la red del clúster de Docker. Un atacante o usuario malintencionado podría enviar cabeceras falsificadas (`Header Spoofing`) y omitir el Gateway, explotando la "Confianza Ciega" del microservicio interno.
* **Mitigación**:
  1. **Aislamiento de Red**: En producción, solo el puerto del Gateway (`8080`) debe estar publicado al exterior. Los microservicios internos no deben tener mapeos de puertos (`ports:` en docker-compose) y solo deben comunicarse en la red interna de Docker.
  2. **Validación de Token en Tránsito**: Los microservicios internos deberían validar un JWT o una firma criptográfica interna (como mTLS o tokens JWS de servicio a servicio) en lugar de depender únicamente de encabezados en texto plano (`X-User-*`).

---

## 3. Flujo Paso a Paso para el Usuario CHOFER

El usuario con el rol **CHOFER** es rechazado en ambos sistemas debido a que su rol carece de los permisos necesarios tanto para **cifrar/enviar** en el Sistema A como para **descifrar/recibir** en el Sistema B.

### A. Rechazo en el Sistema A (Envío/Cifrado)
1. **Intento de Envío**: El Chofer inicia sesión (obtiene un token válido con rol `"CHOFER"`) e interactúa con el portal web haciendo clic en "Enviar Seguro".
2. **Paso por el Gateway**: La petición pasa por el API Gateway, que valida el JWT del Chofer e inyecta el encabezado `X-User-Rol: CHOFER`.
3. **Validación en Sistema A**: La petición llega a `EnvioController.java`.
4. **Evaluación de Seguridad**:
   ```java
   if (!"ADMINISTRADOR".equalsIgnoreCase(rol)) { ... }
   ```
   Dado que `rol` es `"CHOFER"`, la validación se cumple (es verdadero) y retorna inmediatamente un error **`403 Forbidden`** indicando que requiere privilegios de `ADMINISTRADOR`. El descifrado no se solicita al KMS y la trama nunca llega al Sistema B.

### B. Rechazo en el Sistema B (Recepción/Descifrado)
1. **Intento de Recepción**: Si el Chofer intenta evadir el Sistema A y realiza una petición directamente al endpoint de recepción del Sistema B (`/api/b/recibir`) pasando una trama cifrada y su token JWT.
2. **Paso por el Gateway / Headers**: El Gateway inyecta `X-User-Rol: CHOFER` y transmite la llamada a `sistema-b`.
3. **Validación en Sistema B**: En `RecepcionController.java` (líneas 34-38):
   ```java
   if (!"ADMINISTRADOR".equalsIgnoreCase(rol) && !"BODEGUERO".equalsIgnoreCase(rol)) {
       Map<String, String> error = new HashMap<>();
       error.put("error", "Acceso denegado. Se requiere rol de ADMINISTRADOR o BODEGUERO");
       return ResponseEntity.status(403).body(error);
   }
   ```
4. **Evaluación de Seguridad**:
   - `!"ADMINISTRADOR".equalsIgnoreCase("CHOFER")` es `true`.
   - `!"BODEGUERO".equalsIgnoreCase("CHOFER")` es `true`.
   - Como ambas condiciones son `true`, el condicional evalúa a `true` y el Sistema B bloquea el acceso enviando una respuesta **`403 Forbidden`** informando que requiere ser `ADMINISTRADOR` o `BODEGUERO`. El descifrado en Vault KMS es denegado y la información nunca es expuesta en texto claro.

---

### Resumen de Permisos por Rol

| Módulo / Acción | ADMINISTRADOR | BODEGUERO | CHOFER |
| :--- | :---: | :---: | :---: |
| **Cifrar y Enviar (Sistema A)** | ✅ Permitido | ❌ Denegado (`403`) | ❌ Denegado (`403`) |
| **Recibir y Descifrar (Sistema B)** | ✅ Permitido | ✅ Permitido | ❌ Denegado (`403`) |
