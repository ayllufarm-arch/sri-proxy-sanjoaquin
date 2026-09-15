"""Ensayo local completo de la frontera de firma.

Se genera un par RSA de prueba, se firman tokens con el, y se sustituyen las
claves publicas de Google por la de prueba. Asi se ejercita el camino real de
verificacion -- firma, emisor, audiencia, caducidad -- sin tocar Firebase, sin
usuarios reales y sin el certificado fiscal.
"""
import importlib
import time

import jwt
import pytest
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

PROYECTO = "san-joaquin-de-prueba"


@pytest.fixture(scope="module")
def clave():
    """Par RSA con su certificado autofirmado, para ejercitar el camino real de
    verificacion: el codigo carga un X.509 en PEM, igual que hace con los de
    Google. Nada de esto toca Firebase ni el certificado fiscal."""
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "prueba")])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(nombre).issuer_name(nombre)
            .public_key(k.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(ahora - datetime.timedelta(days=1))
            .not_valid_after(ahora + datetime.timedelta(days=1))
            .sign(k, hashes.SHA256()))
    pem_priv = k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).decode()
    pem_cert = cert.public_bytes(serialization.Encoding.PEM).decode()
    return k, pem_priv, pem_cert


@pytest.fixture
def proxy(monkeypatch, clave):
    monkeypatch.setenv("FIREBASE_PROJECT_ID", PROYECTO)
    monkeypatch.setenv("PROXY_AUTH_ENFORCE", "true")
    monkeypatch.setenv("PROXY_API_KEY", "")
    monkeypatch.delenv("P12_B64", raising=False)
    import firebase_auth
    import sri_proxy
    importlib.reload(firebase_auth)
    importlib.reload(sri_proxy)
    # Se inyecta la clave publica de prueba en lugar de ir a Google.
    # Solo se sustituye la descarga: la carga del PEM y la verificacion de firma
    # son las de produccion.
    monkeypatch.setattr(firebase_auth, "_certificados",
                        lambda: {"kid-de-prueba": clave[2]})
    sri_proxy.app.config.update(TESTING=True)
    sri_proxy._rate_store.clear()
    return sri_proxy


def token(clave, *, permisos=None, proyecto=PROYECTO, exp=None):
    ahora = int(time.time())
    payload = {
        "sub": "uid-sintetico", "aud": proyecto,
        "iss": f"https://securetoken.google.com/{proyecto}",
        "iat": ahora, "exp": exp if exp is not None else ahora + 3600,
    }
    if permisos is not None:
        payload["permisos"] = permisos
    return jwt.encode(payload, clave[1], algorithm="RS256",
                      headers={"kid": "kid-de-prueba"})


def firmar(proxy, tok=None):
    h = {"Authorization": f"Bearer {tok}"} if tok else {}
    return proxy.app.test_client().post("/firmar", json={"xmlBase64": "eA=="}, headers=h)


def test_anonimo_401(proxy):
    assert firmar(proxy).status_code == 401


def test_token_valido_sin_permiso_403(proxy, clave):
    """Autenticado no es autorizado. Un cajero entra a admin.html y aun asi no
    puede firmar."""
    r = firmar(proxy, token(clave, permisos=["sri:read"]))
    assert r.status_code == 403


def test_token_sin_claim_de_permisos_403(proxy, clave):
    assert firmar(proxy, token(clave)).status_code == 403


def test_token_autorizado_llega_a_la_capa_de_firma(proxy, clave):
    """Con permiso, la peticion pasa la frontera y falla por sus propios
    motivos -- no hay modulos de firma en el entorno de prueba -- nunca por
    autenticacion."""
    r = firmar(proxy, token(clave, permisos=["invoice:sign"]))
    assert r.status_code not in (401, 403)


def test_token_de_otro_proyecto_401(proxy, clave):
    """Sin comprobar la audiencia, cualquiera crea un proyecto Firebase propio,
    obtiene un token perfectamente firmado por Google, y entra."""
    r = firmar(proxy, token(clave, permisos=["invoice:sign"], proyecto="proyecto-ajeno"))
    assert r.status_code == 401


def test_token_caducado_401(proxy, clave):
    r = firmar(proxy, token(clave, permisos=["invoice:sign"], exp=int(time.time()) - 10))
    assert r.status_code == 401


def test_permiso_en_el_cuerpo_no_sirve(proxy, clave):
    """El cuerpo lo escribe el cliente. Mandar permisos ahi no cambia nada: el
    permiso se lee del token firmado."""
    h = {"Authorization": f"Bearer {token(clave, permisos=['sri:read'])}"}
    r = proxy.app.test_client().post(
        "/firmar", json={"xmlBase64": "eA==", "permisos": ["invoice:sign"],
                         "role": "Administrador", "isAdmin": True},
        headers=h)
    assert r.status_code == 403


def test_localStorage_no_influye_en_el_servidor(proxy, clave):
    """El rol cacheado en localStorage puede editarlo el usuario. No viaja en la
    peticion y el servidor no lo consulta: es solo interfaz."""
    h = {"Authorization": f"Bearer {token(clave, permisos=['sri:read'])}",
         "X-Sj-Role": "Administrador"}
    r = proxy.app.test_client().post("/firmar", json={"xmlBase64": "eA=="}, headers=h)
    assert r.status_code == 403


def test_permisos_son_por_operacion(proxy, clave):
    """Consultar una autorizacion no da derecho a firmar."""
    c = proxy.app.test_client()
    h = {"Authorization": f"Bearer {token(clave, permisos=['sri:read'])}"}
    assert c.post("/autorizacion", json={"claveAcceso": "1"*49}, headers=h).status_code != 403
    assert c.post("/firmar", json={"xmlBase64": "eA=="}, headers=h).status_code == 403


def test_el_token_no_aparece_en_la_respuesta(proxy, clave):
    tok = token(clave, permisos=["sri:read"])
    r = firmar(proxy, tok)
    assert tok not in r.get_data(as_text=True)


def test_el_preflight_no_exige_identidad(proxy):
    """El OPTIONS de un endpoint protegido no puede pedir credenciales.

    Los navegadores nunca mandan Authorization en un preflight. Exigirla ahi
    devuelve 401 al preflight, el navegador bloquea la peticion real antes de
    emitirla y en consola solo aparece "Failed to fetch", sin pista de cual
    request fallo ni por que.

    Ocurrio en produccion el 15-sep-2026 con /send-invoice y /send-email, que
    declaran methods=["POST","OPTIONS"] y por eso el OPTIONS entraba al view
    function. Las rutas declaradas solo POST no lo sufrian porque flask-cors
    atiende su preflight antes.
    """
    cliente = proxy.app.test_client()
    for ruta in ("/firmar", "/recepcion", "/autorizacion", "/send-email", "/send-invoice"):
        r = cliente.open(ruta, method="OPTIONS", headers={
            "Origin": "https://ejemplo.test",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        })
        assert r.status_code not in (401, 403), \
            f"el preflight de {ruta} exige identidad: HTTP {r.status_code}"


def test_el_post_sigue_exigiendo_identidad_tras_permitir_el_preflight(proxy):
    """Dejar pasar OPTIONS no puede abrir el POST. Esa seria la regresion."""
    cliente = proxy.app.test_client()
    for ruta in ("/firmar", "/recepcion", "/autorizacion", "/send-email", "/send-invoice"):
        assert cliente.post(ruta, json={}).status_code == 401, \
            f"{ruta} dejo de exigir identidad en POST"
