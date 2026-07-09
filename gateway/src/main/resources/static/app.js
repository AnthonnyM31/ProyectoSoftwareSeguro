// Consola de Control Seguro — App JS Integration
let keycloak = null;

document.addEventListener("DOMContentLoaded", () => {
    // Inicializar Keycloak Adapter cargando desde el mismo Host/Port del Gateway
    keycloak = new Keycloak({
        url: window.location.origin, // Keycloak expuesto a traves del Gateway
        realm: "tita-realm",
        clientId: "web-control"
    });

    keycloak.init({
        onLoad: "login-required",
        checkLoginIframe: false
    })
    .then(authenticated => {
        if (authenticated) {
            setupAuthenticatedSession();
        } else {
            console.warn("Autenticacion fallida");
        }
    })
    .catch(err => {
        console.error("Error al inicializar Keycloak:", err);
        document.getElementById("tokenBox").innerText = "Fallo la inicialización del servidor de identidades (Keycloak).";
    });

    // Refrescar el token cada 60 segundos
    setInterval(() => {
        if (keycloak && keycloak.token) {
            keycloak.updateToken(70).then(refreshed => {
                if (refreshed) {
                    console.log("Token refrescado");
                    document.getElementById("tokenBox").innerText = keycloak.token;
                }
            }).catch(() => {
                console.error("Fallo al refrescar token");
            });
        }
    }, 60000);
});

function setupAuthenticatedSession() {
    // Mostrar perfil y ocultar cargadores
    document.getElementById("userProfile").style.display = "flex";
    
    const tokenPayload = keycloak.tokenParsed;
    const name = tokenPayload.name || tokenPayload.preferred_username || "Usuario";
    const email = tokenPayload.email || tokenPayload.sub;
    
    // Buscar rol del Realm
    const roles = tokenPayload.realm_access?.roles || [];
    let activeRole = "USUARIO";
    if (roles.includes("ADMINISTRADOR")) activeRole = "ADMINISTRADOR";
    else if (roles.includes("BODEGUERO")) activeRole = "BODEGUERO";
    else if (roles.includes("CHOFER")) activeRole = "CHOFER";

    document.getElementById("profileName").innerText = name;
    document.getElementById("profileRole").innerText = activeRole;
    document.getElementById("profileEmail").innerText = email;
    document.getElementById("tokenBox").innerText = keycloak.token;
}

function handleLogout() {
    if (keycloak) {
        keycloak.logout({ redirectUri: window.location.origin });
    }
}

// Disparador del KMS: Llama a Sistema A enviando el payload
function sendSecureMessage() {
    const rawMessage = document.getElementById("plainMessage").value;
    const btnSend = document.getElementById("btnSend");
    
    let payload = null;
    try {
        payload = JSON.parse(rawMessage);
    } catch (e) {
        // Si no es JSON valido, enviarlo como un objeto con propiedad texto
        payload = { "texto": rawMessage };
    }

    // Mostrar visualizador y resetear pasos anterior
    document.getElementById("kmsVisualizer").style.display = "flex";
    document.getElementById("stepPlain").innerText = JSON.stringify(payload, null, 2);
    document.getElementById("stepCipher").innerText = "Cifrando trama en Sistema A...";
    document.getElementById("stepDecoded").innerText = "Esperando recepcion...";
    
    btnSend.disabled = true;
    
    // Llamar al Sistema A a traves de la ruta segura del Gateway
    fetch("/api/a/enviar", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + keycloak.token
        },
        body: JSON.stringify(payload)
    })
    .then(response => {
        if (!response.ok) {
            throw new Error("HTTP status " + response.status);
        }
        return response.json();
    })
    .then(data => {
        // Rellenar visualizador
        document.getElementById("stepCipher").innerText = data.ciphertextEnviado;
        document.getElementById("stepDecoded").innerText = JSON.stringify(data.respuestaSistemaB, null, 2);
    })
    .catch(err => {
        console.error("Error en flujo seguro:", err);
        document.getElementById("stepCipher").innerText = "Fallo en la comunicación segura.";
        document.getElementById("stepDecoded").innerText = err.message || "Error de red.";
    })
    .finally(() => {
        btnSend.disabled = false;
    });
}
