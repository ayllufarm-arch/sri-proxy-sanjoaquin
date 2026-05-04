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
from email.mime.base import MIMEBase
from email import encoders
from flask import Flask, request, jsonify, redirect
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

P12_B64         = os.environ.get("P12_B64",         "").strip()
P12_PASS        = os.environ.get("P12_PASS",        "").strip()
PAYPHONE_TOKEN  = os.environ.get("PAYPHONE_TOKEN",  "").strip()
LEGACY_PROXY_URL = os.environ.get("LEGACY_PROXY_URL", "").strip().rstrip("/")

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

CORS(app, origins=get_allowed_origins(), methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type"])

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
    if path.startswith("/payphone/") and not PAYPHONE_TOKEN:
        return _forward_to_legacy_proxy()
    if path in ("/enviar-codigo", "/verificar-codigo") and not ((GMAIL_USER and GMAIL_PASSWORD) or RESEND_API_KEY):
        return _forward_to_legacy_proxy()
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
    return jsonify({
        "status":                "ok",
        "servicio":              "SRI Proxy v2 — San Joaquín Artesanía Cárnica",
        "firma_tipo":            "XAdES-BES 1.3.2 ENVELOPED",
        "firma_disponible":      FIRMA_DISPONIBLE,
        "p12_en_servidor":       bool(P12_B64),
        "payphone_configurado":  bool(PAYPHONE_TOKEN),
        "payphone_local":        bool(PAYPHONE_TOKEN),
        "cors_origin":           ALLOWED_ORIGIN,
        "gmail_configurado":     bool(GMAIL_USER and GMAIL_PASSWORD),
        "resend_configurado":    bool(RESEND_API_KEY),
        "send_email_endpoint":   True,
        "email_configurado":     bool((GMAIL_USER and GMAIL_PASSWORD) or RESEND_API_KEY),
        "legacy_fallback":       bool(LEGACY_PROXY_URL),
        "admin_email":           ADMIN_EMAIL,
    })


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
@cross_origin()
def payphone_link():
    """
    Proxy para generar un link de pago vía PayPhone (API Links).
    Body JSON: { token, amount, amountWithoutTax, amountWithTax, tax,
                 currency, storeId, reference, clientTransactionId }
    Respuesta: URL string (ej. https://payp.page.link/aYu55)
    """
    data  = request.get_json(force=True, silent=True) or {}
    token = PAYPHONE_TOKEN or data.pop("token", "")
    if not token:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado en el servidor"}), 500
    else:
        data.pop("token", None)  # descartar si vino en el body
    try:
        # Guardar token por txId para poder auto-confirmar cuando PayPhone redirige
        tx_id = data.get('clientTransactionId', '')
        if tx_id:
            _token_store[tx_id] = {"token": token, "timestamp": time.time()}
            logger.info(f"Token guardado para txId={tx_id}")

        webhook_url = request.url_root.rstrip('/') + '/payphone/webhook'
        data.setdefault('notifyUrl', webhook_url)
        data.setdefault('confirmPaymentUrl', webhook_url)
        logger.info(f"PayPhone /api/Links token prefix: {token[:12]}... storeId: {data.get('storeId')} amount: {data.get('amount')}")
        resp = requests.post(
            "https://pay.payphonetodoesposible.com/api/Links",
            json=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15
        )
        logger.info(f"PayPhone /api/Links response {resp.status_code}: {resp.text[:300]}")
        return (resp.text, resp.status_code, {"Content-Type": "text/plain"})
    except requests.exceptions.Timeout:
        return jsonify({"error": "PayPhone no respondió a tiempo"}), 504
    except Exception as e:
        logger.exception("Error en /payphone/link")
        return jsonify({"error": str(e)}), 500


@app.route("/payphone/confirm", methods=["POST", "OPTIONS"])
@cross_origin()
def payphone_confirm():
    """
    Consulta el estado de un pago por clientTransactionId.
    Body JSON: { token, clientTransactionId }
    Respuesta: JSON de PayPhone con transactionStatus (3=aprobado, 2=anulado, 1=pendiente)
    """
    data  = request.get_json(force=True, silent=True) or {}
    token = PAYPHONE_TOKEN or data.pop("token", "")
    data.pop("token", None)
    ctxid = data.get("clientTransactionId", "")
    if not token or not ctxid:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado y clientTransactionId requerido"}), 400
    try:
        resp = requests.get(
            f"https://pay.payphonetodoesposible.com/api/sale/client/{ctxid}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15
        )
        logger.info(f"PayPhone confirm {ctxid}: {resp.status_code} {resp.text[:200]}")
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
    logger.info(f"[Webhook] Body: {raw_body[:800]}")

    if request.method in ('GET', 'OPTIONS'):
        # PayPhone redirige el NAVEGADOR del cliente aquí después del pago.
        tx_id      = request.args.get('clientTransactionId', '')
        pp_id      = request.args.get('id', '')
        payment_id = request.args.get('paymentId', '')
        logger.info(f"[Webhook GET] Redirect de PayPhone: txId={tx_id} id={pp_id}")

        # AUTO-CONFIRMAR con /api/button/Confirm usando el token guardado al crear el link.
        # Debe llamarse dentro de los 5 minutos post-pago o PayPhone revierte la transacción.
        stored = _token_store.get(tx_id, {})
        token  = stored.get("token", "")
        if token and pp_id:
            try:
                conf_resp = requests.post(
                    "https://pay.payphonetodoesposible.com/api/button/Confirm",
                    json={"id": int(pp_id), "clientTransactionId": tx_id},
                    headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                    timeout=10
                )
                raw_conf = conf_resp.text
                logger.info(f"[Auto-Confirm] {pp_id}/{tx_id}: HTTP {conf_resp.status_code} → {raw_conf[:300]}")
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
        logger.warning(f"[Webhook] Sin clientTransactionId — body: {raw_body[:300]}")

    return jsonify({"estado": "OK"}), 200


@app.route("/payphone/debug", methods=["GET"])
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


@app.route("/payphone/confirmed/<path:tx_id>", methods=["GET", "OPTIONS"])
@cross_origin()
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


@app.route("/payphone/button-confirm", methods=["POST", "OPTIONS"])
@cross_origin()
def payphone_button_confirm():
    """
    Confirma una transacción via /api/button/Confirm.
    OBLIGATORIO dentro de 5 min post-pago o PayPhone revierte.
    Body: { token, id (numeric), clientTransactionId }
    """
    data  = request.get_json(force=True, silent=True) or {}
    token = PAYPHONE_TOKEN or data.pop("token", "")
    data.pop("token", None)
    if not token:
        return jsonify({"error": "PAYPHONE_TOKEN no configurado en el servidor"}), 500
    try:
        logger.info(f"PayPhone button/Confirm payload: {data}")
        resp = requests.post(
            "https://pay.payphonetodoesposible.com/api/button/Confirm",
            json=data,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            timeout=15
        )
        logger.info(f"PayPhone button/Confirm: HTTP {resp.status_code} → {resp.text[:400]}")
        return (resp.text, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        logger.exception("Error en /payphone/button-confirm")
        return jsonify({"error": str(e)}), 500


@app.route("/payphone/status", methods=["POST", "OPTIONS"])
def payphone_status():
    """
    Proxy para consultar el estado de un pago.
    Body JSON: { token, transactionId }
    """
    data  = request.get_json(force=True, silent=True) or {}
    token = PAYPHONE_TOKEN or data.pop("token", "")
    data.pop("token", None)
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
