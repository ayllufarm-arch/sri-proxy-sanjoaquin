#!/usr/bin/env python3
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

import os
import logging
import re
import base64
import tempfile
import smtplib
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from functools import wraps
from collections import defaultdict
import time

# Firma digital (XMLDSig para SRI Ecuador)
try:
    from lxml import etree
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from signxml import XMLSigner, methods
    FIRMA_DISPONIBLE = True
except Exception as e:
    FIRMA_DISPONIBLE = False
    logging.warning(f"Módulos de firma no disponibles: {e}. Instala: pip install lxml signxml cryptography")

# ─── CONFIGURACIÓN ────────────────────────────────────────────────────────────

app = Flask(__name__)

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "http://localhost")
LOG_LEVEL      = os.environ.get("LOG_LEVEL", "INFO").upper()
PORT           = int(os.environ.get("PORT", 5000))
GMAIL_USER     = os.environ.get("GMAIL_USER", "")
GMAIL_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL", "ayllu.farm@gmail.com")

# Certificado digital opcional en variables de entorno (más seguro que enviarlo desde el browser)
# Si están configuradas, /firmar las usa y NO requiere p12Base64/p12Password en el body.
P12_B64  = os.environ.get("P12_B64",  "").strip()
P12_PASS = os.environ.get("P12_PASS", "").strip()

# Almacén de códigos de verificación en memoria: { email: { code, expires } }
_verification_codes: dict = {}

# CORS restringido al dominio configurado
# En desarrollo acepta localhost con cualquier puerto
def get_allowed_origins():
    base = [ALLOWED_ORIGIN]
    if "localhost" in ALLOWED_ORIGIN or "127.0.0.1" in ALLOWED_ORIGIN:
        base += [
            "http://localhost",
            "http://127.0.0.1",
            re.compile(r"http://localhost:\d+"),
            re.compile(r"http://127\.0\.0\.1:\d+"),
        ]
    return base

CORS(app, origins=get_allowed_origins(), methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type"])

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("sri_proxy")

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


def call_sri(url: str, soap_body: str) -> str:
    """Realiza la llamada SOAP al SRI y devuelve la respuesta en texto."""
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'}
    resp = requests.post(url, data=soap_body.encode("utf-8"), headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.text

# ─── EMAIL ────────────────────────────────────────────────────────────────────

def send_verification_email(code: str) -> bool:
    """Envía el código de verificación a ADMIN_EMAIL vía Gmail SMTP."""
    if not GMAIL_USER or not GMAIL_PASSWORD:
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
    Firma un comprobante XML con el certificado .p12 del SRI Ecuador.

    Algoritmo: RSA-SHA1 (requerido por SRI Ecuador).
    Retorna el XML firmado como string UTF-8.

    Referencia: Ficha técnica SRI — Comprobantes Electrónicos versión 2.21
    """
    if not FIRMA_DISPONIBLE:
        raise RuntimeError("Módulos de firma no instalados (lxml, signxml, cryptography)")

    # Cargar certificado .p12
    private_key, certificate, chain = pkcs12.load_key_and_certificates(
        p12_bytes, p12_password, backend=default_backend()
    )

    # Serializar clave privada y certificado a PEM para signxml
    key_pem  = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

    # Parsear XML
    root = etree.fromstring(xml_bytes)

    # Firmar con XMLDSig — enveloped signature (requerido por SRI)
    signer = XMLSigner(
        method=methods.enveloped,
        signature_algorithm="rsa-sha1",
        digest_algorithm="sha1",
        c14n_algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    )

    signed_root = signer.sign(
        root,
        key=key_pem,
        cert=cert_pem,
    )

    return etree.tostring(signed_root, xml_declaration=True, encoding="UTF-8").decode("utf-8")


@app.route("/enviar-codigo", methods=["POST"])
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
    if not GMAIL_USER or not GMAIL_PASSWORD:
        return jsonify({
            "error": "El servidor de correo no está configurado.",
            "solucion": "Configura GMAIL_USER y GMAIL_APP_PASSWORD en las variables de entorno."
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
        return jsonify({"error": "No se pudo enviar el correo. Revisa la configuración SMTP."}), 502

    # Ocultar parte del email en la respuesta (privacidad)
    parts   = ADMIN_EMAIL.split("@")
    masked  = parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else "***"
    return jsonify({"estado": "OK", "destino": masked})


@app.route("/verificar-codigo", methods=["POST"])
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


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":              "ok",
        "servicio":            "SRI Proxy v2 — San Joaquín Artesanía Cárnica",
        "firma_disponible":    FIRMA_DISPONIBLE,
        "p12_en_servidor":     bool(P12_B64),
        "cors_origin":         ALLOWED_ORIGIN,
        "email_configurado":   bool(GMAIL_USER and GMAIL_PASSWORD),
        "admin_email":         ADMIN_EMAIL,
    })


@app.route("/firmar", methods=["POST"])
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

@app.route("/payphone/link", methods=["POST", "OPTIONS"])
def payphone_link():
    """
    Proxy para generar un link de pago vía PayPhone (API Links).
    Body JSON: { token, amount, amountWithoutTax, amountWithTax, tax,
                 currency, storeId, reference, clientTransactionId }
    Respuesta: URL string (ej. https://payp.page.link/aYu55)
    """
    data  = request.get_json(force=True, silent=True) or {}
    token = data.pop("token", "")
    if not token:
        return jsonify({"error": "Token de PayPhone requerido"}), 400
    try:
        resp = requests.post(
            "https://pay.payphonetodoesposible.com/api/Links",
            json=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15
        )
        # PayPhone devuelve la URL como texto plano
        return (resp.text, resp.status_code, {"Content-Type": "text/plain"})
    except requests.exceptions.Timeout:
        return jsonify({"error": "PayPhone no respondió a tiempo"}), 504
    except Exception as e:
        logger.exception("Error en /payphone/link")
        return jsonify({"error": str(e)}), 500


@app.route("/payphone/status", methods=["POST", "OPTIONS"])
def payphone_status():
    """
    Proxy para consultar el estado de un pago.
    Body JSON: { token, transactionId }
    """
    data  = request.get_json(force=True, silent=True) or {}
    token = data.pop("token", "")
    tid   = data.get("transactionId", "")
    if not token or not tid:
        return jsonify({"error": "token y transactionId requeridos"}), 400
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
