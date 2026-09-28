#!/usr/bin/env python3
# BUILD_VERSION: 2026-05-04-v2
"""
sri_proxy.py — Proxy CORS + Firma Digital para Web Services SRI Ecuador
San Joaquín Artesanía Cárnica

Instalación:
    pip install flask flask-cors requests lxml signxml cryptography

Variables de entorno:
    ALLOWED_ORIGIN   — URL del panel admin (ej: https://admin.tudominio.com)
    PORT             — Puerto (default 5000, Railway/Render lo inyectan)
    LOG_LEVEL        — DEBUG | INFO | WARNING (default INFO)
    P12_B64          — Certificado .p12 en base64 (RECOMENDADO: más seguro que enviarlo
                       desde el navegador). Si está configurado, /firmar lo usa
                       automáticamente y no requiere p12Base64 en el body.
    P12_PASS         — Contraseña del certificado .p12 (texto plano, solo se usa si
                       P12_B64 está configurado)

Despliegue en Railway/Render:
    1. Sube este archivo + requirements.txt + Procfile
    2. Set ALLOWED_ORIGIN a tu dominio real
    3. El servidor arranca con: gunicorn sri_proxy:app

Endpoints:
    GET  /health        — Verificar que el proxy esté activo
    POST /firmar        — Firmar XML con certificado .p12 (XMLDSig)
    POST /recepcion     — Enviar comprobante XML firmado al SRI
    POST /autorizacion  — Consultar autorización por clave de acceso
"""

import hmac
import os
import logging
import re
import base64
import tempfile
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
# Import defensivo, siguiendo el mismo patron que los modulos de firma de abajo.
# Este repo tiene nueve commits peleando con la cache de build de Railway: si una
# dependencia nueva no se instala, un import duro tumba el servicio entero y el
# negocio no puede facturar. Degradar es preferible a no arrancar.
try:
    import firebase_auth
    IDENTIDAD_DISPONIBLE = True
except Exception as _e:  # noqa: BLE001
    firebase_auth = None
    IDENTIDAD_DISPONIBLE = False
    logging.warning("Verificacion de identidad no disponible: %s", _e)

from flask import Flask, g, request, jsonify, redirect
from flask_cors import CORS, cross_origin
import requests
from functools import wraps
from collections import defaultdict
import time

# Firma digital (XAdES-BES para SRI Ecuador)
try:
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    from sri_xades_signer import sign_xml
    FIRMA_DISPONIBLE = True
except Exception as e:
    FIRMA_DISPONIBLE = False
    logging.warning(f"Módulos de firma no disponibles: {e}. Instala: pip install lxml signxml cryptography")

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────

app = Flask(__name__)

ALLOWED_ORIGIN = (os.environ.get("ALLOWED_ORIGIN") or os.environ.get("CORS_ORIGIN") or "http://localhost").strip()
STORE_URL      = os.environ.get("STORE_URL", "https://san-joaquin-artesania-carnica.web.app").strip()
LOG_LEVEL      = os.environ.get("LOG_LEVEL", "INFO").upper()
PORT           = int(os.environ.get("PORT", 5000))
GMAIL_USER     = os.environ.get("GMAIL_USER", "")
GMAIL_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL", "ayllu.farm@gmail.com")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
RESEND_FROM    = os.environ.get("RESEND_FROM", "facturacion@sanjoaquinartesaniacarnica.com").strip()
RESEND_FROM_NAME = os.environ.get("RESEND_FROM_NAME", "San Joaquin Artesania Carnica").strip()

# ── Control de acceso a endpoints privilegiados ───────────────────────────────
# PROXY_API_KEY      — secreto compartido. Vacio = control INACTIVO.
# PROXY_AUTH_ENFORCE — "true" para exigirlo. Separado de la presencia de la clave
#                      a proposito: permite desplegar, observar en logs quien
#                      llama sin credencial, y recien entonces cerrar. Encenderlo
#                      antes de migrar al consumidor deja al negocio sin facturar.
# FIREBASE_PROJECT_ID — identifica el proyecto cuyos tokens se aceptan. NO es un
# secreto: es publico y aparece en el HTML. Se comprueba para que un token de
# otro proyecto de Firebase no sirva aqui.
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
PROXY_API_KEY   = os.environ.get("PROXY_API_KEY",   "").strip()
AUTH_ENFORCE = PROXY_AUTH_ENFORCE = os.environ.get("PROXY_AUTH_ENFORCE", "").strip().lower() == "true"

P12_B64         = os.environ.get("P12_B64",         "").strip()
P12_PASS        = os.environ.get("P12_PASS",        "").strip()
PAYPHONE_TOKEN  = os.environ.get("PAYPHONE_TOKEN",  "").strip()
LEGACY_PROXY_URL = os.environ.get("LEGACY_PROXY_URL", "").strip().rstrip("/")
# Credencial de servicio del backend de San Joaquín (Firebase Functions) para las operaciones de
# pagos. Distinta de PROXY_API_KEY (mantenimiento) y de los tokens de Firebase del personal.
PROXY_PAGOS_KEY = os.environ.get("PROXY_PAGOS_KEY", "").strip()

_verification_codes: dict = {}
_confirmed_payments: dict = {}   # clientTransactionId -> {confirmed, timestamp, statusCode, raw}
_token_store: dict       = {}   # clientTransactionId -> {token, timestamp}  para auto-confirmar

def get_allowed_origins():
    # Soporta múltiples orígenes separados por coma en ALLOWED_ORIGIN
    raw = ALLOWED_ORIGIN
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    extra = []
    for o in origins:
        if "localhost" in o or "127.0.0.1" in o:
            extra += [
                "http://localhost",
                "http://127.0.0.1",
                re.compile(r"http://localhost:\d+"),
                re.compile(r"http://127\.0\.0\.1:\d+"),
            ]
    return origins + extra

# `Authorization` tiene que estar aqui o el navegador nunca llega a enviar la
# peticion: el preflight responde sin permitirla y el fetch muere antes de
# salir. Mientras admin.html usaba `fetch` plano solo hacia falta Content-Type;
# desde que usa proxyFetch, cada llamada fiscal manda el ID token de Firebase.
CORS(app, origins=get_allowed_origins(), methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("sri_proxy")


def _forward_to_legacy_proxy():
    """Reenvia integraciones no migradas al proxy anterior sin exponer secretos."""
    if not LEGACY_PROXY_URL:
        return None
    url = LEGACY_PROXY_URL + request.full_path
    if url.endswith("?"):
        url = url[:-1]
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    try:
        resp = requests.request(
            request.method,
            url,
            data=request.get_data(),
            headers=headers,
            timeout=30,
            allow_redirects=False,
        )
        return (
            resp.content,
            resp.status_code,
            {"Content-Type": resp.headers.get("Content-Type", "application/json")},
        )
    except Exception as e:
        logger.exception(f"Error reenviando a proxy legado {url}: {e}")
        return jsonify({"error": "No se pudo conectar con el proxy legado"}), 502


@app.before_request
def legacy_proxy_fallback():
    """Mantiene PayPhone/correos/admin activos si sus secretos siguen en el proxy viejo."""
    if request.method == "OPTIONS":
        return None
    path = request.path
    # Solo el webhook (público, lo llama PayPhone) puede reenviarse: el resto de /payphone/* exige
    # la credencial de servicio o la interna, y reenviarlo saltaría esa comprobación.
    if path == "/payphone/webhook" and not PAYPHONE_TOKEN:
        return _forward_to_legacy_proxy()
    # /enviar-codigo y /verificar-codigo ya no se reenvían: son internos y el reenvío saltaría esa
    # comprobación (el mismo motivo que con los pagos).
    if path == "/send-invoice" and not RESEND_API_KEY:
        return _forward_to_legacy_proxy()
    return None

# ─── URLs SRI ────────────────────────────────────────────────────────────────

ENDPOINTS = {
    "pruebas": {
        "recepcion":    "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline",
        "autorizacion": "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline",
    },
    "produccion": {
        "recepcion":    "https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline",
        "autorizacion": "https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline",
    },
}

TIMEOUT = 30  # segundos

# ─── RATE LIMITING (simple, en memoria) ──────────────────────────────────────
# Máx 20 solicitudes por IP por minuto
RATE_LIMIT     = 20
RATE_WINDOW    = 60  # segundos
_rate_store    = defaultdict(list)

def requiere_identidad(permiso):
    """Exige un ID token de Firebase valido y un permiso fiscal concreto.

    Sustituye a la credencial compartida para las llamadas que vienen del
    navegador. La diferencia importa: un secreto compartido en el navegador es un
    secreto publicado, mientras que un ID token es del usuario, caduca solo y
    dice quien es.

    401 si no hay identidad. 403 si la hay pero no alcanza. Son casos distintos y
    conviene que el operador los distinga.
    """
    def decorador(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # El preflight NUNCA lleva credenciales: los navegadores no envian
            # Authorization en un OPTIONS. Si se le exige identidad, se responde
            # 401 al preflight y el navegador bloquea la peticion real antes de
            # emitirla; en la consola aparece "Failed to fetch", sin pista.
            # Las rutas declaradas solo POST no sufrian esto porque flask-cors
            # atiende su OPTIONS antes de llegar aqui.
            if request.method == "OPTIONS":
                return app.make_default_options_response()
            cabecera = request.headers.get("Authorization", "")
            token = cabecera[7:].strip() if cabecera.lower().startswith("bearer ") else ""
            # La compatibilidad con la credencial servidor-a-servidor se mantiene
            # a proposito: permite migrar el navegador sin cortar nada.
            if PROXY_API_KEY and hmac.compare_digest(
                    request.headers.get("X-Proxy-Key", ""), PROXY_API_KEY):
                return f(*args, **kwargs)
            if not IDENTIDAD_DISPONIBLE:
                # Sin el modulo no se puede verificar a nadie. En modo
                # observacion se deja pasar, como hasta ahora; con la exigencia
                # activa se cierra, porque no verificar no es autorizar.
                logger.warning("Identidad no verificable en %s: modulo ausente",
                               request.path)
                if AUTH_ENFORCE:
                    return jsonify({"error": "Verificacion no disponible"}), 503
                return f(*args, **kwargs)
            try:
                claims = firebase_auth.verificar_id_token(token, FIREBASE_PROJECT_ID)
            except firebase_auth.AuthError as e:
                # Se registra el motivo y la ruta, nunca el token ni un fragmento.
                logger.warning("Identidad rechazada en %s: %s", request.path, e.motivo)
                if AUTH_ENFORCE:
                    return jsonify({"error": e.motivo}), e.http
                return f(*args, **kwargs)
            if not firebase_auth.tiene_permiso(claims, permiso):
                logger.warning("uid %s sin permiso %s en %s",
                               claims.get("sub", "?")[:8], permiso, request.path)
                if AUTH_ENFORCE:
                    return jsonify({"error": "Sin permiso para esta operacion"}), 403
            g.uid = claims.get("sub")
            return f(*args, **kwargs)
        return decorated
    return decorador


def solo_interno(f):
    """Cierra un endpoint que ningun navegador llama. Siempre.

    Distinto de `requiere_credencial`: aquel respeta el interruptor de
    compatibilidad, porque los endpoints fiscales los llama admin.html y cerrarlos
    antes de migrar el navegador dejaria al negocio sin facturar. Estos no: nadie
    los llama desde un navegador, asi que no hay nada que migrar y no hay motivo
    para que dependan de una bandera.

    Ese acoplamiento fue un error mio de diseno: ate toda la proteccion a un solo
    interruptor por uniformidad, y el resultado fue que /cert-info y
    /payphone/debug quedaron publicos en produccion despues del despliegue de
    contencion.

    Falla cerrado. Si PROXY_API_KEY no esta configurada, se rechaza: una
    configuracion ausente no puede convertir un endpoint interno en publico.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "OPTIONS":
            return app.make_default_options_response()
        if not PROXY_API_KEY:
            logger.error("Endpoint interno %s sin PROXY_API_KEY configurada: "
                         "se rechaza por defecto", request.path)
            return jsonify({"error": "No disponible"}), 503
        if not hmac.compare_digest(request.headers.get("X-Proxy-Key", ""), PROXY_API_KEY):
            logger.warning("Acceso interno rechazado en %s", request.path)
            return jsonify({"error": "No autorizado"}), 401
        return f(*args, **kwargs)
    return decorated


# --- pagos: solo el backend, con autorización por operación ------------------
CABECERA_PAGOS = "X-SJ-Servicio-Pagos"
# Qué operación representa cada endpoint de pagos. Todas exigen la credencial de servicio del
# backend; ninguna acepta el token de Firebase del personal, la clave interna PROXY_API_KEY ni una
# petición anónima. El webhook de PayPhone queda fuera: lo llama PayPhone y no devuelve datos.
OPERACIONES_PAGOS = {
    "crear_enlace": "/payphone/link",
    "consultar": ("/payphone/confirm", "/payphone/status", "/payphone/confirmed/<tx>"),
    "confirmar": "/payphone/button-confirm",
}


def solo_servicio_pagos(operacion):
    """Cierra una operación de pagos a todo lo que no sea el backend de San Joaquín.

    Falla cerrado: sin PROXY_PAGOS_KEY configurada (32+ caracteres) responde 503. Nunca registra la
    credencial recibida ni la esperada.
    """
    if operacion not in OPERACIONES_PAGOS:
        raise ValueError(f"Operación de pagos desconocida: {operacion}")

    def envolver(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if len(PROXY_PAGOS_KEY) < 32:
                logger.error("Pagos: %s sin PROXY_PAGOS_KEY configurada: se rechaza por defecto", request.path)
                return jsonify({"error": "Servicio de pagos no disponible"}), 503
            recibida = request.headers.get(CABECERA_PAGOS, "")
            if not recibida:
                logger.warning("Pagos: peticion sin credencial de servicio en %s (%s)", request.path, operacion)
                return jsonify({"error": "Credencial de servicio requerida"}), 401
            if not hmac.compare_digest(recibida.encode("utf-8"), PROXY_PAGOS_KEY.encode("utf-8")):
                logger.warning("Pagos: credencial de servicio invalida en %s (%s)", request.path, operacion)
                return jsonify({"error": "Credencial de servicio invalida"}), 403
            return f(*args, **kwargs)
        return decorated
    return envolver


def requiere_credencial(f):
    """Exige un secreto compartido en cabecera para endpoints privilegiados.

    No acepta el secreto por query string: las URLs acaban en logs de acceso, en
    el historial del navegador y en cabeceras Referer.

    Comparacion en tiempo constante, para no filtrar el secreto por temporizacion.
    El valor recibido nunca se registra, ni truncado.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        recibido = request.headers.get("X-Proxy-Key", "")
        valido = bool(PROXY_API_KEY) and hmac.compare_digest(recibido, PROXY_API_KEY)
        if not valido:
            logger.warning("Peticion sin credencial valida a %s (enforce=%s)",
                           request.path, PROXY_AUTH_ENFORCE)
            if PROXY_AUTH_ENFORCE:
                return jsonify({"error": "No autorizado"}), 401
        return f(*args, **kwargs)
    return decorated


def rate_limited(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip  = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
        now = time.time()
        # Limpiar entradas antiguas
        _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
        if len(_rate_store[ip]) >= RATE_LIMIT:
            logger.warning(f"Rate limit excedido para IP: {ip}")
            return jsonify({"error": "Demasiadas solicitudes. Espera un momento."}), 429
        _rate_store[ip].append(now)
        return f(*args, **kwargs)
    return decorated

# ─── HELPERS SOAP ─────────────────────────────────────────────────────────────

def build_soap_recepcion(xml_comprobante_b64: str) -> str:
    """Construye el sobre SOAP para enviar un comprobante."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope'
        ' xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
        ' xmlns:ec="http://ec.gob.sri.ws.recepcion">'
        '<soapenv:Header/>'
        '<soapenv:Body>'
        '<ec:validarComprobante>'
        f'<xml>{xml_comprobante_b64}</xml>'
        '</ec:validarComprobante>'
        '</soapenv:Body>'
        '</soapenv:Envelope>'
    )


def build_soap_autorizacion(clave_acceso: str) -> str:
    """Construye el sobre SOAP para consultar autorización."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope'
        ' xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
        ' xmlns:ec="http://ec.gob.sri.ws.autorizacion">'
        '<soapenv:Header/>'
        '<soapenv:Body>'
        '<ec:autorizacionComprobante>'
        f'<claveAccesoComprobante>{clave_acceso}</claveAccesoComprobante>'
        '</ec:autorizacionComprobante>'
        '</soapenv:Body>'
        '</soapenv:Envelope>'
    )


def call_sri(url: str, soap_body: str, retries: int = 2) -> str:
    """Realiza la llamada SOAP al SRI con reintentos automáticos."""
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'}
    last_exc = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(url, data=soap_body.encode("utf-8"), headers=headers, timeout=TIMEOUT)
            resp.raise_for_status()
            return resp.text
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_exc = e
            if attempt < retries:
                logger.warning(f"Intento {attempt+1} fallido → {e}. Reintentando en 3s…")
                time.sleep(3)
        except Exception as e:
            raise
    raise last_exc

# ─── EMAIL ────────────────────────────────────────────────────────────────────

def send_resend_verification_email(code: str) -> bool:
    """Send the admin verification code through Resend."""
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:32px;
                border:1px solid #e0e0e0;border-radius:8px;">
      <h2 style="color:#c0392b;margin-top:0;">San Joaquin Artesania Carnica</h2>
      <p>Se solicito crear una cuenta de administrador en el sistema.</p>
      <div style="background:#f8f8f8;border-radius:6px;padding:20px;text-align:center;
                  font-size:36px;font-weight:bold;letter-spacing:8px;color:#222;">
        {code}
      </div>
      <p style="color:#888;font-size:13px;margin-top:20px;">
        Este codigo expira en <strong>10 minutos</strong>.<br>
        Si no solicitaste esto, ignora este mensaje.
      </p>
    </div>"""
    try:
        payload = {
            "from": f"{RESEND_FROM_NAME} <{RESEND_FROM}>",
            "to": [ADMIN_EMAIL],
            "subject": f"[San Joaquin] Codigo de verificacion: {code}",
            "html": html,
        }
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )
        logger.info(f"Resend codigo admin -> {ADMIN_EMAIL}: HTTP {resp.status_code} {resp.text[:200]}")
        return resp.status_code in (200, 201)
    except Exception as e:
        logger.error(f"Error enviando codigo por Resend: {e}")
        return False


def send_verification_email(code: str) -> bool:
    """Envia el codigo de verificacion a ADMIN_EMAIL por Resend o Gmail SMTP."""
    if RESEND_API_KEY:
        return send_resend_verification_email(code)
    if not ((GMAIL_USER and GMAIL_PASSWORD) or RESEND_API_KEY):
        logger.warning("GMAIL_USER o GMAIL_APP_PASSWORD no configurados")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[San Joaquín] Código de verificación: {code}"
        msg["From"]    = GMAIL_USER
        msg["To"]      = ADMIN_EMAIL

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:32px;
                    border:1px solid #e0e0e0;border-radius:8px;">
          <h2 style="color:#c0392b;margin-top:0;">San Joaquín Artesanía Cárnica</h2>
          <p>Se solicitó crear una cuenta de administrador en el sistema.</p>
          <div style="background:#f8f8f8;border-radius:6px;padding:20px;text-align:center;
                      font-size:36px;font-weight:bold;letter-spacing:8px;color:#222;">
            {code}
          </div>
          <p style="color:#888;font-size:13px;margin-top:20px;">
            Este código expira en <strong>10 minutos</strong>.<br>
            Si no solicitaste esto, ignora este mensaje.
          </p>
        </div>"""

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_PASSWORD)
            server.sendmail(GMAIL_USER, ADMIN_EMAIL, msg.as_string())

        logger.info(f"Código de verificación enviado a {ADMIN_EMAIL}")
        return True
    except Exception as e:
        logger.error(f"Error enviando email: {e}")
        return False


# ─── RUTAS ───────────────────────────────────────────────────────────────────

def firmar_xml_sri(xml_bytes: bytes, p12_bytes: bytes, p12_password: bytes) -> str:
    """
    Firma XMLDSig manual para SRI Ecuador:
      - Reference URI="#comprobante", enveloped-signature
      - RSA-SHA1, digest SHA1
      - C14N no exclusivo (http://www.w3.org/TR/2001/REC-xml-c14n-20010315)

    Implementación manual porque signxml 2.x no resuelve atributos 'id' en minúscula.
    """
    if not FIRMA_DISPONIBLE:
        raise RuntimeError("Modulos de firma XAdES no instalados")

    password_text = p12_password.decode("utf-8") if isinstance(p12_password, bytes) else (p12_password or "")
    xml_text = xml_bytes.decode("utf-8")
    signed_xml = sign_xml(
        pkcs12_file=p12_bytes,
        password=password_text,
        xml=xml_text,
        read_file=False,
    )
    if isinstance(signed_xml, bytes):
        signed_xml = signed_xml.decode("utf-8")
    if "http://uri.etsi.org/01903/v1.3.2#" not in signed_xml:
        raise RuntimeError("La firma generada no contiene XAdES-BES 1.3.2")
    if "SignedProperties" not in signed_xml or "QualifyingProperties" not in signed_xml:
        raise RuntimeError("La firma generada no contiene propiedades XAdES")
    return signed_xml

    import hashlib
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    if not FIRMA_DISPONIBLE:
        raise RuntimeError("Módulos de firma no instalados (lxml, cryptography)")

    private_key, certificate, _ = pkcs12.load_key_and_certificates(
        p12_bytes, p12_password, backend=default_backend()
    )

    cert_b64 = base64.b64encode(
        certificate.public_bytes(serialization.Encoding.DER)
    ).decode("ascii")

    DSIG     = "http://www.w3.org/2000/09/xmldsig#"
    C14N_URL = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

    # 1. Parsear el XML original
    root = etree.fromstring(xml_bytes)

    # 2. C14N del elemento raíz (Signature aún no existe) → DigestValue
    c14n_root = etree.tostring(root, method="c14n", exclusive=False, with_comments=False)
    digest_b64 = base64.b64encode(hashlib.sha1(c14n_root).digest()).decode("ascii")

    # 3. Construir el árbol Signature dentro del root
    def sub(parent, tag):
        return etree.SubElement(parent, f"{{{DSIG}}}{tag}")

    sig  = sub(root, "Signature")
    si   = sub(sig,  "SignedInfo")
    cm   = sub(si,   "CanonicalizationMethod"); cm.set("Algorithm", C14N_URL)
    sm   = sub(si,   "SignatureMethod");        sm.set("Algorithm", f"{DSIG}rsa-sha1")
    ref  = sub(si,   "Reference");              ref.set("URI", "#comprobante")
    trs  = sub(ref,  "Transforms")
    tr   = sub(trs,  "Transform");              tr.set("Algorithm", f"{DSIG}enveloped-signature")
    dm   = sub(ref,  "DigestMethod");           dm.set("Algorithm", f"{DSIG}sha1")
    dv   = sub(ref,  "DigestValue");            dv.text = digest_b64
    sv   = sub(sig,  "SignatureValue");         sv.text = ""   # placeholder
    ki   = sub(sig,  "KeyInfo")
    x9d  = sub(ki,   "X509Data")
    x9c  = sub(x9d,  "X509Certificate");        x9c.text = cert_b64

    # 4. C14N de SignedInfo EN CONTEXTO del documento (hereda xmlns de Signature padre)
    c14n_si = etree.tostring(si, method="c14n", exclusive=False, with_comments=False)

    # 5. Firmar SignedInfo con RSA-SHA1
    sig_bytes = private_key.sign(c14n_si, asym_padding.PKCS1v15(), crypto_hashes.SHA1())
    sv.text   = base64.b64encode(sig_bytes).decode("ascii")

    return etree.tostring(root, xml_declaration=True, encoding="UTF-8").decode("utf-8")


# /enviar-codigo y /verificar-codigo eran del alta de cuentas desde el navegador, que la web ya no tiene
# (el alta la hace el backend). Anónimos, cualquiera podía hacer enviar correos a administración (el
# límite por IP se elude con X-Forwarded-For). Quedan solo para mantenimiento: exigen PROXY_API_KEY y,
# sin ella configurada, responden 503 sin enviar nada.
@app.route("/enviar-codigo", methods=["POST"])
@solo_interno
@rate_limited
def enviar_codigo():
    """
    Genera y envía un código de verificación de 6 dígitos a ADMIN_EMAIL.

    Body JSON:
        { "motivo": "primer-admin" | "nuevo-usuario" }

    Respuesta OK:
        { "estado": "OK", "destino": "a***@gmail.com" }

    El código se guarda en memoria por 10 minutos.
    """
    if not ((GMAIL_USER and GMAIL_PASSWORD) or RESEND_API_KEY):
        return jsonify({
            "error": "El servidor de correo no está configurado.",
            "solucion": "Configura RESEND_API_KEY o GMAIL_USER/GMAIL_APP_PASSWORD en las variables de entorno."
        }), 501

    # Limpiar códigos expirados
    now = time.time()
    expired = [k for k, v in _verification_codes.items() if now > v["expires"]]
    for k in expired:
        del _verification_codes[k]

    code = str(secrets.randbelow(900000) + 100000)  # 100000–999999
    _verification_codes[ADMIN_EMAIL] = {
        "code":    code,
        "expires": now + 600,  # 10 minutos
    }

    ok = send_verification_email(code)
    if not ok:
        return jsonify({"error": "No se pudo enviar el correo. Revisa la configuracion de Resend o SMTP."}), 502

    # Ocultar parte del email en la respuesta (privacidad)
    parts   = ADMIN_EMAIL.split("@")
    masked  = parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else "***"
    return jsonify({"estado": "OK", "destino": masked})


@app.route("/verificar-codigo", methods=["POST"])
@solo_interno
@rate_limited
def verificar_codigo():
    """
    Verifica que el código ingresado por el usuario sea correcto.

    Body JSON:
        { "codigo": "123456" }

    Respuesta OK:
        { "estado": "OK" }
    """
    data   = request.get_json(force=True, silent=True) or {}
    codigo = str(data.get("codigo", "")).strip()

    if not codigo:
        return jsonify({"error": "El campo codigo es obligatorio"}), 400

    now    = time.time()
    entry  = _verification_codes.get(ADMIN_EMAIL)

    if not entry:
        return jsonify({"error": "No hay código activo. Solicita uno nuevo."}), 400
    if now > entry["expires"]:
        del _verification_codes[ADMIN_EMAIL]
        return jsonify({"error": "El código expiró. Solicita uno nuevo."}), 400
    if entry["code"] != codigo:
        return jsonify({"error": "Código incorrecto. Verifica tu correo."}), 400

    # Código correcto — invalidarlo inmediatamente (uso único)
    del _verification_codes[ADMIN_EMAIL]
    logger.info("Código de verificación validado OK")
    return jsonify({"estado": "OK"})


@app.route("/cert-info", methods=["GET"])
@solo_interno
def cert_info():
    """Muestra información del certificado configurado en P12_B64 (sin exponer clave privada)."""
    if not P12_B64:
        return jsonify({"error": "P12_B64 no configurado en variables de entorno"}), 400
    try:
        p12_bytes = base64.b64decode(P12_B64)
        password  = P12_PASS.encode("utf-8") if P12_PASS else None
        _, cert, chain = pkcs12.load_key_and_certificates(p12_bytes, password, backend=default_backend())
        from datetime import timezone
        now = __import__("datetime").datetime.now(timezone.utc)
        info = {
            "subject":      cert.subject.rfc4514_string(),
            "issuer":       cert.issuer.rfc4514_string(),
            "serial":       str(cert.serial_number),
            "not_before":   cert.not_valid_before_utc.isoformat(),
            "not_after":    cert.not_valid_after_utc.isoformat(),
            "expired":      now > cert.not_valid_after_utc,
            "valid_now":    cert.not_valid_before_utc <= now <= cert.not_valid_after_utc,
            "chain_certs":  len(chain) if chain else 0,
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Disponibilidad, y nada mas.

    Publicaba si habia certificado cargado, si PayPhone estaba configurado, que
    proveedor de correo se usaba y la version del build. Nada de eso lo necesita
    un consumidor legitimo: el unico que llama aqui es la sonda de la
    plataforma, y a esa le basta un 200.

    Anunciar `p12_en_servidor: true` le decia a cualquiera que el certificado
    fiscal estaba cargado en ese proceso. No es explotable por si solo, pero es
    la clase de dato que convierte un objetivo generico en uno concreto.

    Para diagnostico interno esta /cert-info, que exige PROXY_API_KEY y falla
    cerrado.
    """
    return jsonify({"status": "ok"})


@app.route("/test-sri", methods=["GET"])
def test_sri():
    """Verifica la conectividad con los servidores del SRI desde Railway."""
    resultados = {}
    for env, urls in ENDPOINTS.items():
        for tipo, url in urls.items():
            key = f"{env}/{tipo}"
            try:
                r = requests.get(url + "?wsdl", timeout=10)
                resultados[key] = {"ok": True, "http": r.status_code}
            except requests.exceptions.ConnectionError as e:
                resultados[key] = {"ok": False, "error": "ConnectionError", "detalle": str(e)[:120]}
            except requests.exceptions.Timeout:
                resultados[key] = {"ok": False, "error": "Timeout"}
            except Exception as e:
                resultados[key] = {"ok": False, "error": type(e).__name__, "detalle": str(e)[:120]}
    todo_ok = all(v["ok"] for v in resultados.values())
    return jsonify({"conectividad": "OK" if todo_ok else "FALLO", "endpoints": resultados}), 200


@app.route("/firmar", methods=["POST"])
@requiere_identidad("invoice:sign")
@rate_limited
def firmar():
    """
    Firma un comprobante XML con el certificado .p12 del emisor.

    Body JSON (multipart/form-data o JSON con base64):
        {
            "xmlBase64":   "<comprobante XML sin firmar, en base64>",
            "p12Base64":   "<archivo .p12 del certificado, en base64>",
            "p12Password": "<contraseña del .p12 en texto plano>"
        }

    Respuesta:
        { "estado": "OK", "xmlFirmadoBase64": "<XML firmado en base64>" }

    SEGURIDAD: El certificado .p12 NO se almacena en el servidor.
    Se procesa en memoria y se descarta inmediatamente.
    Usa HTTPS en producción para proteger la transmisión.
    """
    if not FIRMA_DISPONIBLE:
        return jsonify({
            "error": "El servidor no tiene los módulos de firma instalados.",
            "solucion": "Ejecuta: pip install lxml signxml cryptography"
        }), 501

    data         = request.get_json(force=True, silent=True) or {}
    xml_b64      = data.get("xmlBase64", "").strip()

    if not xml_b64:
        return jsonify({"error": "El campo xmlBase64 es obligatorio"}), 400

    # Prefer server-side certificate (env vars) over client-supplied one
    if P12_B64:
        p12_b64      = P12_B64
        p12_password = P12_PASS.encode("utf-8")
    else:
        p12_b64      = data.get("p12Base64",   "").strip()
        p12_password = data.get("p12Password", "").encode("utf-8")
        if not p12_b64:
            return jsonify({"error": "El campo p12Base64 es obligatorio (o configura P12_B64 en variables de entorno)"}), 400

    try:
        xml_bytes = base64.b64decode(xml_b64)
        p12_bytes = base64.b64decode(p12_b64)
    except Exception:
        return jsonify({"error": "Error decodificando base64. Verifica que xmlBase64 y p12Base64 sean válidos."}), 400

    try:
        logger.info("Firmando comprobante XML...")
        xml_firmado = firmar_xml_sri(xml_bytes, p12_bytes, p12_password)
        xml_firmado_b64 = base64.b64encode(xml_firmado.encode("utf-8")).decode("utf-8")
        logger.info("Comprobante firmado OK")
        return jsonify({"estado": "OK", "xmlFirmadoBase64": xml_firmado_b64})
    except ValueError as e:
        logger.error(f"Error de certificado: {e}")
        return jsonify({"error": f"Error con el certificado .p12: {str(e)}"}), 400
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 501
    except Exception as e:
        logger.exception("Error inesperado al firmar")
        return jsonify({"error": "Error interno al firmar el comprobante"}), 500


@app.route("/recepcion", methods=["POST"])
@requiere_identidad("sri:issue")
@rate_limited
def recepcion():
    """
    Envía un comprobante electrónico al SRI.

    Body JSON:
        {
            "ambiente":  "pruebas" | "produccion",
            "xmlBase64": "<comprobante XML firmado, codificado en base64>"
        }

    Respuesta:
        { "estado": "OK", "respuestaSRI": "<XML de respuesta del SRI>" }
    """
    data    = request.get_json(force=True, silent=True) or {}
    ambiente = data.get("ambiente", "pruebas").strip().lower()
    xml_b64  = data.get("xmlBase64", "").strip()

    if not xml_b64:
        return jsonify({"error": "El campo xmlBase64 es obligatorio"}), 400
    if ambiente not in ENDPOINTS:
        return jsonify({"error": f"Ambiente inválido: '{ambiente}'. Use 'pruebas' o 'produccion'"}), 400

    url  = ENDPOINTS[ambiente]["recepcion"]
    soap = build_soap_recepcion(xml_b64)

    try:
        logger.info(f"Recepción [{ambiente}] → {url}")
        respuesta = call_sri(url, soap)
        logger.info("Recepción OK")
        return jsonify({"estado": "OK", "respuestaSRI": respuesta})
    except requests.exceptions.Timeout:
        logger.error("Timeout en /recepcion")
        return jsonify({"error": "El SRI no respondió a tiempo (timeout 30s)"}), 504
    except requests.exceptions.ConnectionError as e:
        logger.error(f"ConnectionError en /recepcion: {e}")
        return jsonify({"error": "No se pudo conectar al SRI. Verifique la conexión a internet."}), 502
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else "?"
        logger.error(f"HTTPError en /recepcion: {code}")
        return jsonify({"error": f"El SRI devolvió error HTTP {code}"}), 502
    except Exception as e:
        logger.exception("Error inesperado en /recepcion")
        return jsonify({"error": "Error interno del servidor"}), 500


@app.route("/autorizacion", methods=["POST"])
@requiere_identidad("sri:read")
@rate_limited
def autorizacion():
    """
    Consulta el estado de autorización de un comprobante.

    Body JSON:
        {
            "ambiente":    "pruebas" | "produccion",
            "claveAcceso": "<49 dígitos>"
        }

    Respuesta:
        { "estado": "OK", "respuestaSRI": "<XML de respuesta del SRI>" }
    """
    data      = request.get_json(force=True, silent=True) or {}
    ambiente  = data.get("ambiente", "pruebas").strip().lower()
    clave     = data.get("claveAcceso", "").strip()

    if not clave:
        return jsonify({"error": "El campo claveAcceso es obligatorio"}), 400
    if not clave.isdigit() or len(clave) != 49:
        return jsonify({"error": f"claveAcceso debe tener exactamente 49 dígitos numéricos (recibidos: {len(clave)})"}), 400
    if ambiente not in ENDPOINTS:
        return jsonify({"error": f"Ambiente inválido: '{ambiente}'. Use 'pruebas' o 'produccion'"}), 400

    url  = ENDPOINTS[ambiente]["autorizacion"]
    soap = build_soap_autorizacion(clave)

    try:
        logger.info(f"Autorización [{ambiente}] clave: {clave[:8]}…")
        respuesta = call_sri(url, soap)
        logger.info("Autorización OK")
        return jsonify({"estado": "OK", "respuestaSRI": respuesta})
    except requests.exceptions.Timeout:
        logger.error("Timeout en /autorizacion")
        return jsonify({"error": "El SRI no respondió a tiempo (timeout 30s)"}), 504
    except requests.exceptions.ConnectionError as e:
        logger.error(f"ConnectionError en /autorizacion: {e}")
        return jsonify({"error": "No se pudo conectar al SRI."}), 502
    except requests.exceptions.HTTPError as e:
        code = e.response.status_code if e.response else "?"
        logger.error(f"HTTPError en /autorizacion: {code}")
        return jsonify({"error": f"El SRI devolvió error HTTP {code}"}), 502
    except Exception as e:
        logger.exception("Error inesperado en /autorizacion")
        return jsonify({"error": "Error interno del servidor"}), 500


# ─── PAYPHONE PROXY ──────────────────────────────────────────────────────────

@app.route("/payphone/link", methods=["POST"])
@solo_servicio_pagos("crear_enlace")
def payphone_link():
    """
    Proxy para generar un link de pago vía PayPhone (API Links).
    Body JSON: { token, amount, amountWithoutTax, amountWithTax, tax,
                 currency, storeId, reference, clientTransactionId }
    Respuesta: URL string (ej. https://payp.page.link/aYu55)
    """
    data  = request.get_json(force=True, silent=True) or {}
    data.pop("token", None)  # el token solo sale del servidor
    token = PAYPHONE_TOKEN
    if not token:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado en el servidor"}), 500
    try:
        # Guardar token por txId para poder auto-confirmar cuando PayPhone redirige
        tx_id = data.get('clientTransactionId', '')
        if tx_id:
            _token_store[tx_id] = {"token": token, "timestamp": time.time()}
            logger.info(f"Token guardado para txId={tx_id}")

        webhook_url = request.url_root.rstrip('/') + '/payphone/webhook'
        data.setdefault('notifyUrl', webhook_url)
        data.setdefault('confirmPaymentUrl', webhook_url)
        logger.info("PayPhone /api/Links storeId=%s amount=%s", data.get("storeId"), data.get("amount"))
        resp = requests.post(
            "https://pay.payphonetodoesposible.com/api/Links",
            json=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15
        )
        logger.info("PayPhone /api/Links: HTTP %s", resp.status_code)
        return (resp.text, resp.status_code, {"Content-Type": "text/plain"})
    except requests.exceptions.Timeout:
        return jsonify({"error": "PayPhone no respondió a tiempo"}), 504
    except Exception as e:
        logger.exception("Error en /payphone/link")
        return jsonify({"error": str(e)}), 500


@app.route("/payphone/confirm", methods=["POST"])
@solo_servicio_pagos("consultar")
def payphone_confirm():
    """
    Consulta el estado de un pago por clientTransactionId.
    Body JSON: { token, clientTransactionId }
    Respuesta: JSON de PayPhone con transactionStatus (3=aprobado, 2=anulado, 1=pendiente)
    """
    data  = request.get_json(force=True, silent=True) or {}
    data.pop("token", None)
    token = PAYPHONE_TOKEN
    ctxid = data.get("clientTransactionId", "")
    if not token or not ctxid:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado y clientTransactionId requerido"}), 400
    try:
        resp = requests.get(
            f"https://pay.payphonetodoesposible.com/api/sale/client/{ctxid}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        logger.info("PayPhone confirm %s: HTTP %s", ctxid, resp.status_code)  # sin datos del pagador
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        logger.exception("Error en /payphone/confirm")
        return jsonify({"error": str(e)}), 500


@app.route("/payphone/webhook", methods=["POST", "GET", "OPTIONS"])
@cross_origin()
def payphone_webhook():
    """
    Recibe la Notificación Externa de PayPhone cuando un pago es aprobado.
    PayPhone hace POST a esta URL automáticamente (server-to-server).
    Configura esta URL en el portal PayPhone → Configuración → Notificaciones externas.
    También se inyecta como notifyUrl/confirmPaymentUrl en cada link de pago.
    """
    raw_body = request.data.decode('utf-8', errors='replace')
    logger.info(f"[Webhook] Recibido: method={request.method} content-type={request.content_type}")
    logger.info("[Webhook] %s bytes recibidos", len(raw_body))  # sin datos del pagador

    if request.method in ('GET', 'OPTIONS'):
        # PayPhone redirige el NAVEGADOR del cliente aquí después del pago.
        tx_id      = request.args.get('clientTransactionId', '')
        pp_id      = request.args.get('id', '')
        payment_id = request.args.get('paymentId', '')
        logger.info(f"[Webhook GET] Redirect de PayPhone: txId={tx_id} id={pp_id}")

        # PayPhone no firma sus notificaciones -- su documentacion solo exige
        # HTTPS -- asi que este Confirm es ademas la comprobacion de
        # autenticidad: un aviso inventado no confirma contra su API.
        # AUTO-CONFIRMAR con /api/button/Confirm.
        # Debe llamarse dentro de los 5 minutos post-pago o PayPhone revierte la transacción.
        # El token se deriva del entorno, no de la memoria del proceso. Con dos
        # workers de gunicorn lo que guardaba uno no existia para el otro, asi
        # que la confirmacion dependia de que PayPhone volviera al mismo worker.
        # Es la misma credencial: al crear el link se usa PAYPHONE_TOKEN.
        token = PAYPHONE_TOKEN or _token_store.get(tx_id, {}).get("token", "")
        if token and pp_id:
            try:
                conf_resp = requests.post(
                    "https://pay.payphonetodoesposible.com/api/button/Confirm",
                    json={"id": int(pp_id), "clientTransactionId": tx_id},
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    timeout=10
                )
                raw_conf = conf_resp.text
                logger.info("[Auto-Confirm] %s/%s: HTTP %s", pp_id, tx_id, conf_resp.status_code)
                try:
                    conf_data = conf_resp.json()
                    if isinstance(conf_data, list):
                        conf_data = conf_data[0] if conf_data else {}
                    aprobado = (conf_data.get("statusCode") == 3 or
                                str(conf_data.get("statusCode")) == "3" or
                                conf_data.get("transactionStatus") == "Approved")
                except Exception:
                    aprobado = False
                    conf_data = {}
                _confirmed_payments[tx_id] = {
                    "confirmed":         aprobado,
                    "timestamp":         time.time(),
                    "statusCode":        conf_data.get("statusCode"),
                    "transactionStatus": conf_data.get("transactionStatus"),
                    "transactionId":     pp_id,
                    "source":            "auto-confirm",
                }
                logger.info(f"[Auto-Confirm] txId={tx_id} aprobado={aprobado}")
            except Exception as e:
                logger.exception(f"[Auto-Confirm] Error: {e}")
        else:
            logger.warning(f"[Auto-Confirm] Sin token para txId={tx_id} — no se puede confirmar")

        # Redirigir al store con los params para que también procese en el navegador
        store_redirect = f"{STORE_URL}?id={pp_id}&clientTransactionId={tx_id}&paymentId={payment_id}"
        return redirect(store_redirect, code=302)

    data = request.get_json(force=True, silent=True) or {}
    if not data:
        data = request.form.to_dict()

    tx_id = str(data.get("clientTransactionId",
                data.get("ClientTransactionId",
                data.get("client_transaction_id", "")))).strip()
    status_code   = data.get("statusCode", data.get("StatusCode", data.get("status_code")))
    tx_status     = str(data.get("transactionStatus", data.get("TransactionStatus", ""))).strip()
    numeric_tid   = data.get("id", data.get("transactionId", ""))

    aprobado = (status_code == 3 or str(status_code) == "3" or
                tx_status.lower() in ("approved", "aprobado"))

    logger.info(f"[Webhook] txId={tx_id} numericId={numeric_tid} statusCode={status_code} status={tx_status} aprobado={aprobado}")

    if tx_id:
        _confirmed_payments[tx_id] = {
            "confirmed":         aprobado,
            "timestamp":         time.time(),
            "statusCode":        status_code,
            "transactionStatus": tx_status,
            "transactionId":     numeric_tid,
            "raw":               data,
        }
        logger.info(f"[Webhook] Guardado en memoria: txId={tx_id} confirmed={aprobado}")
    else:
        logger.warning("[Webhook] Sin clientTransactionId (%s bytes)", len(raw_body))

    return jsonify({"estado": "OK"}), 200


@app.route("/payphone/debug", methods=["GET"])
@solo_interno
@cross_origin()
def payphone_debug():
    """Muestra pagos recibidos vía webhook (solo para diagnóstico)."""
    resultado = {}
    for k, v in _confirmed_payments.items():
        resultado[k] = {
            "confirmed": v.get("confirmed"),
            "statusCode": v.get("statusCode"),
            "transactionStatus": v.get("transactionStatus"),
            "ageSeconds": int(time.time() - v.get("timestamp", 0)),
        }
    return jsonify({"webhooks_recibidos": len(resultado), "pagos": resultado}), 200


@app.route("/payphone/confirmed/<path:tx_id>", methods=["GET"])
@solo_servicio_pagos("consultar")
def payphone_confirmed(tx_id):
    """
    Consulta si un pago fue confirmado vía webhook de PayPhone.
    El frontend hace polling a este endpoint cada pocos segundos.
    """
    tx_id = tx_id.strip()
    entry = _confirmed_payments.get(tx_id)

    if not entry:
        return jsonify({"confirmed": False, "found": False}), 200

    age = time.time() - entry.get("timestamp", 0)
    if age > 7200:   # expira a las 2 horas
        del _confirmed_payments[tx_id]
        return jsonify({"confirmed": False, "expired": True}), 200

    return jsonify({
        "confirmed":         entry.get("confirmed", False),
        "found":             True,
        "statusCode":        entry.get("statusCode"),
        "transactionStatus": entry.get("transactionStatus"),
        "transactionId":     entry.get("transactionId"),
        "ageSeconds":        int(age),
    }), 200


@app.route("/payphone/button-confirm", methods=["POST"])
@solo_servicio_pagos("confirmar")
def payphone_button_confirm():
    """
    Confirma una transacción via /api/button/Confirm.
    OBLIGATORIO dentro de 5 min post-pago o PayPhone revierte.
    Body: { token, id (numeric), clientTransactionId }
    """
    data  = request.get_json(force=True, silent=True) or {}
    data.pop("token", None)
    token = PAYPHONE_TOKEN
    if not token:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado en el servidor"}), 500
    try:
        logger.info("PayPhone button/Confirm txId=%s", data.get("clientTransactionId", ""))
        resp = requests.post(
            "https://pay.payphonetodoesposible.com/api/button/Confirm",
            json=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15
        )
        logger.info("PayPhone button/Confirm: HTTP %s", resp.status_code)
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        logger.exception("Error en /payphone/button-confirm")
        return jsonify({"error": str(e)}), 500


@app.route("/payphone/status", methods=["POST"])
@solo_servicio_pagos("consultar")
def payphone_status():
    """
    Proxy para consultar el estado de un pago.
    Body JSON: { token, transactionId }
    """
    data  = request.get_json(force=True, silent=True) or {}
    data.pop("token", None)
    token = PAYPHONE_TOKEN
    tid   = data.get("transactionId", "")
    if not token or not tid:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado y transactionId requerido"}), 400
    try:
        resp = requests.get(
            f"https://pay.payphonetodoesposible.com/api/sale?transactionId={tid}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        logger.exception("Error en /payphone/status")
        return jsonify({"error": str(e)}), 500


# ─── ENVÍO DE FACTURAS VÍA RESEND ────────────────────────────────────────────

@app.route("/send-invoice", methods=["POST", "OPTIONS"])
@requiere_identidad("invoice:send")
@cross_origin()
@rate_limited
def send_invoice():
    """
    Envía un comprobante de venta por correo usando Resend API (HTTPS).

    Body JSON:
        {
            "to":         "cliente@email.com",
            "folio":      "FAC-044",
            "clientName": "Juan Pérez",
            "pdfBase64":  "<base64 del PDF>",
            "xmlBase64":  "<base64 del XML autorizado>"  (opcional),
            "xmlFilename": "..."  (opcional),
            "subject":    "..."  (opcional)
        }
    """
    if not RESEND_API_KEY:
        return jsonify({"error": "RESEND_API_KEY no configurada en el servidor"}), 501

    data    = request.get_json(force=True, silent=True) or {}
    to      = str(data.get("to", "")).strip()
    folio   = str(data.get("folio", "Comprobante")).strip()
    name    = str(data.get("clientName", "Cliente")).strip()
    pdf_b64 = str(data.get("pdfBase64", "")).strip()
    xml_b64 = str(data.get("xmlBase64", "")).strip()
    xml_filename = str(data.get("xmlFilename", "")).strip() or f"{folio}.xml"
    extra_attachments = data.get("extraAttachments") or []

    if not to or not pdf_b64:
        return jsonify({"error": "Campos 'to' y 'pdfBase64' son obligatorios"}), 400

    subject = data.get("subject") or f"Comprobante de compra {folio} - San Joaquin Artesania Carnica"
    attachment_note = (
        "Adjuntamos el RIDE en PDF y el XML autorizado por el SRI."
        if xml_b64 or extra_attachments
        else "Adjuntamos el RIDE en PDF."
    )

    html_body = f"""
    <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#222;">
      <div style="background:#8B1A1A;padding:20px 28px;border-radius:8px 8px 0 0;">
        <h2 style="color:#fff;margin:0;font-size:20px;">San Joaquín Artesanía Cárnica</h2>
      </div>
      <div style="padding:24px 28px;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px;">
        <p style="margin:0 0 16px;">Estimado/a <strong>{name}</strong>,</p>
        <p style="margin:0 0 16px;">
          Adjunto encontrará su comprobante de compra <strong>{folio}</strong>.<br>
          {attachment_note}<br>
          Gracias por preferirnos.
        </p>
        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
        <p style="font-size:12px;color:#888;margin:0;">
          San Joaquín Artesanía Cárnica · Galo Plaza Lasso Km13 vía a Cayambe
        </p>
      </div>
    </div>"""

    try:
        attachments = [{"filename": f"{folio}.pdf", "content": pdf_b64, "content_type": "application/pdf"}]
        if xml_b64:
            attachments.append({"filename": xml_filename, "content": xml_b64, "content_type": "application/xml"})
        if isinstance(extra_attachments, list):
            for att in extra_attachments:
                if not isinstance(att, dict):
                    continue
                filename = str(att.get("filename") or att.get("name") or "").strip()
                content = str(att.get("content") or "").strip()
                if filename and content and not any(a.get("filename") == filename for a in attachments):
                    attachments.append({
                        "filename": filename,
                        "content": content,
                        "content_type": str(att.get("content_type") or "application/octet-stream")
                    })

        payload = {
            "from": f"{RESEND_FROM_NAME} <{RESEND_FROM}>",
            "to":   [to],
            "subject": subject,
            "html": html_body,
            "attachments": attachments
        }
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=15
        )
        logger.info(f"Resend {folio} → {to}: HTTP {resp.status_code} {resp.text[:200]}")
        if resp.status_code in (200, 201):
            return jsonify({"estado": "OK", "mensaje": f"Correo enviado a {to}", "attachments": len(attachments)})
        err = resp.json().get("message", resp.text)
        return jsonify({"error": err}), resp.status_code
    except Exception as e:
        logger.exception("Error enviando factura por Resend")
        return jsonify({"error": str(e)}), 500


@app.route("/send-email", methods=["POST", "OPTIONS"])
@requiere_identidad("email:send")
@cross_origin()
@rate_limited
def send_email():
    """
    Envía un correo genérico usando Resend API.

    Body JSON:
        {
            "to":          [{"email":"...", "name":"..."}],
            "subject":     "...",
            "html":        "...",
            "attachments": [{"filename":"...", "content":"<base64>"}]  (opcional)
        }
    """
    if not RESEND_API_KEY:
        return jsonify({"error": "RESEND_API_KEY no configurada en el servidor"}), 501

    data        = request.get_json(force=True, silent=True) or {}
    to_raw      = data.get("to", [])
    subject     = str(data.get("subject", "Notificación — San Joaquín")).strip()
    html_body   = str(data.get("html", "")).strip()
    attachments = data.get("attachments", [])

    if not to_raw or not html_body:
        return jsonify({"error": "Campos 'to' y 'html' son obligatorios"}), 400

    to_list = []
    for r in (to_raw if isinstance(to_raw, list) else [to_raw]):
        if isinstance(r, dict):
            email = r.get("email", "")
            name  = r.get("name", "")
            to_list.append(f"{name} <{email}>" if name else email)
        else:
            to_list.append(str(r))

    try:
        payload = {
            "from":    f"San Joaquín Artesanía Cárnica <{RESEND_FROM}>",
            "to":      to_list,
            "subject": subject,
            "html":    html_body,
        }
        if attachments:
            payload["attachments"] = attachments

        resp = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json=payload,
            timeout=15,
        )
        logger.info(f"send-email → {to_list}: HTTP {resp.status_code}")
        if resp.status_code in (200, 201):
            return jsonify({"estado": "OK", "mensaje": f"Correo enviado a {len(to_list)} destinatario(s)"})
        err = resp.json().get("message", resp.text) if resp.content else "Error desconocido"
        return jsonify({"error": err}), resp.status_code
    except Exception as e:
        logger.exception("Error en /send-email")
        return jsonify({"error": str(e)}), 500


# ─── MAIN ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  SRI Proxy v2 — San Joaquín Artesanía Cárnica")
    print("=" * 60)
    print(f"  Puerto     : {PORT}")
    print(f"  CORS origin: {ALLOWED_ORIGIN}")
    print(f"  Log level  : {LOG_LEVEL}")
    print()
    print("  Endpoints:")
    print("    GET  /health")
    print("    POST /recepcion     { ambiente, xmlBase64 }")
    print("    POST /autorizacion  { ambiente, claveAcceso }")
    print()
    print("  Para producción usa gunicorn:")
    print("    gunicorn sri_proxy:app --bind 0.0.0.0:$PORT")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=(LOG_LEVEL == "DEBUG"))
