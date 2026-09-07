"""Verificacion de identidad de Firebase dentro del proxy.

La pregunta que resuelve este modulo es si se puede cerrar el P0 sin levantar un
servidor nuevo. La respuesta es que si, y la razon es que un ID token de Firebase
es un JWT RS256 firmado por Google: se verifica contra **claves publicas**, no
contra un secreto. El proxy no necesita ninguna credencial nueva para saber quien
llama.

Lo que si necesita un origen de autoridad es el PERMISO. Y ahi la eleccion
importa: leer el rol de Firestore obligaria a meter una cuenta de servicio en el
proxy -- un secreto nuevo, con acceso a toda la base. En cambio un **custom claim**
viaja firmado dentro del propio token, asi que verificarlo no cuesta ninguna
credencial adicional y el usuario no puede alterarlo: cambiarlo exige la clave
privada de Google.

Por eso la autorizacion se apoya en un claim, no en una lectura de Firestore.

Ningun secreto vive aqui. Las claves publicas se descargan de Google y se
cachean respetando su Cache-Control.
"""

import time
import threading

import jwt
import requests
from cryptography.x509 import load_pem_x509_certificate

# Certificados publicos con los que Google firma los ID tokens.
_CERTS_URL = ("https://www.googleapis.com/robot/v1/metadata/x509/"
              "securetoken@system.gserviceaccount.com")
_ISSUER_TPL = "https://securetoken.google.com/{project}"

_cache = {"certs": None, "expira": 0.0}
_lock = threading.Lock()


class AuthError(Exception):
    """Motivo de rechazo. El texto es apto para devolver al cliente: nunca
    contiene el token ni parte de el."""
    def __init__(self, motivo, http=401):
        super().__init__(motivo)
        self.motivo = motivo
        self.http = http


def _certificados():
    ahora = time.time()
    with _lock:
        if _cache["certs"] and ahora < _cache["expira"]:
            return _cache["certs"]
    r = requests.get(_CERTS_URL, timeout=10)
    r.raise_for_status()
    # Google indica cuanto duran; se respeta en vez de inventar un TTL.
    edad = 3600
    cc = r.headers.get("Cache-Control", "")
    for parte in cc.split(","):
        if "max-age" in parte:
            try:
                edad = int(parte.split("=")[1])
            except (IndexError, ValueError):
                pass
    with _lock:
        _cache["certs"] = r.json()
        _cache["expira"] = ahora + max(300, edad)
        return _cache["certs"]


def verificar_id_token(token, project_id, ahora=None):
    """Devuelve las claims si el token es autentico y vigente.

    Comprueba firma, emisor, audiencia, caducidad y que el sujeto exista. Un
    token de otro proyecto de Firebase se rechaza aunque su firma sea valida:
    sin esa comprobacion cualquiera podria crear un proyecto propio y entrar.
    """
    if not project_id:
        raise AuthError("Servicio sin proyecto de Firebase configurado", 503)
    if not token:
        raise AuthError("Falta el token de identidad")

    try:
        cabecera = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AuthError("Token ilegible")

    kid = cabecera.get("kid")
    certs = _certificados()
    if kid not in certs:
        raise AuthError("Token firmado con una clave desconocida")

    clave = load_pem_x509_certificate(certs[kid].encode()).public_key()

    try:
        claims = jwt.decode(
            token, clave, algorithms=["RS256"],
            audience=project_id,
            issuer=_ISSUER_TPL.format(project=project_id),
            options={"require": ["exp", "iat", "aud", "iss", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("Token caducado")
    except jwt.InvalidAudienceError:
        raise AuthError("Token de otro proyecto")
    except jwt.InvalidIssuerError:
        raise AuthError("Emisor no valido")
    except jwt.PyJWTError:
        raise AuthError("Token no valido")

    if not claims.get("sub"):
        raise AuthError("Token sin identidad")
    return claims


def tiene_permiso(claims, permiso):
    """El permiso viaja firmado dentro del token, como custom claim.

    Nunca se lee del cuerpo de la peticion ni de una cabecera: eso lo controla
    quien llama. Un claim solo lo puede poner el Admin SDK con la clave privada
    de Google.
    """
    permisos = claims.get("permisos") or []
    if not isinstance(permisos, list):
        return False
    return permiso in permisos
