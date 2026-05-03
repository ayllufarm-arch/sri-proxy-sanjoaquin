import base64
import os
import urllib.error
import urllib.request

from flask import Flask, jsonify, request
from flask_cors import CORS
from sri_xades_signer import sign_xml


app = Flask(__name__)
CORS(app, origins=[o.strip() for o in os.getenv("CORS_ORIGIN", "*").split(",") if o.strip()])


SRI = {
    "pruebas": {
        "recepcion": "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline",
        "autorizacion": "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline",
    },
    "produccion": {
        "recepcion": "https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline",
        "autorizacion": "https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantesOffline",
    },
}


def _env_bool(name):
    return bool(os.getenv(name, "").strip())


def _json_error(message, status=400):
    return jsonify({"error": message}), status


def _post_soap(url, envelope):
    body = envelope.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": "",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"SRI HTTP {e.code}: {detail[:1000]}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"No se pudo conectar con SRI: {e.reason}") from e


def _get_ambiente(raw):
    ambiente = (raw or "pruebas").strip().lower()
    if ambiente in ("2", "prod", "produccion", "producción"):
        return "produccion"
    return "pruebas"


def _decode_xml(xml_base64):
    if not xml_base64:
        raise ValueError("Falta xmlBase64")
    return base64.b64decode(xml_base64).decode("utf-8")


def _assert_xades(signed_xml):
    if "http://uri.etsi.org/01903/v1.3.2#" not in signed_xml:
        raise ValueError("La firma generada no contiene XAdES-BES 1.3.2")
    if "SignedProperties" not in signed_xml or "QualifyingProperties" not in signed_xml:
        raise ValueError("La firma generada no contiene propiedades XAdES")


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "servicio": "SRI Proxy XAdES-BES",
            "firma_tipo": "XAdES-BES 1.3.2 ENVELOPED",
            "firma_disponible": _env_bool("P12_B64") and _env_bool("P12_PASS"),
            "p12_en_servidor": _env_bool("P12_B64"),
        }
    )


@app.post("/firmar")
def firmar():
    data = request.get_json(silent=True) or {}
    try:
        xml_text = _decode_xml(data.get("xmlBase64"))
        p12_b64 = data.get("p12Base64") or os.getenv("P12_B64", "")
        p12_pass = data.get("p12Password") or os.getenv("P12_PASS", "")
        if not p12_b64:
            return _json_error("Falta p12Base64 o variable P12_B64", 400)
        if not p12_pass:
            return _json_error("Falta p12Password o variable P12_PASS", 400)

        p12_bytes = base64.b64decode(p12_b64)
        signed_xml = sign_xml(
            pkcs12_file=p12_bytes,
            password=p12_pass,
            xml=xml_text,
            read_file=False,
        )
        if isinstance(signed_xml, bytes):
            signed_xml = signed_xml.decode("utf-8")
        _assert_xades(signed_xml)

        return jsonify(
            {
                "estado": "FIRMADO",
                "xmlFirmadoBase64": base64.b64encode(signed_xml.encode("utf-8")).decode("ascii"),
            }
        )
    except Exception as e:
        return _json_error(f"Error firmando XML: {e}", 500)


@app.post("/recepcion")
def recepcion():
    data = request.get_json(silent=True) or {}
    ambiente = _get_ambiente(data.get("ambiente"))
    xml_base64 = data.get("xmlBase64")
    if not xml_base64:
        return _json_error("Falta xmlBase64", 400)

    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.recepcion">
  <soapenv:Header/>
  <soapenv:Body>
    <ec:validarComprobante>
      <xml>{xml_base64}</xml>
    </ec:validarComprobante>
  </soapenv:Body>
</soapenv:Envelope>"""
    try:
        respuesta = _post_soap(SRI[ambiente]["recepcion"], envelope)
        return jsonify({"estado": "OK", "respuestaSRI": respuesta})
    except Exception as e:
        return _json_error(str(e), 502)


@app.post("/autorizacion")
def autorizacion():
    data = request.get_json(silent=True) or {}
    ambiente = _get_ambiente(data.get("ambiente"))
    clave = (data.get("claveAcceso") or "").strip()
    if not clave:
        return _json_error("Falta claveAcceso", 400)

    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ec="http://ec.gob.sri.ws.autorizacion">
  <soapenv:Header/>
  <soapenv:Body>
    <ec:autorizacionComprobante>
      <claveAccesoComprobante>{clave}</claveAccesoComprobante>
    </ec:autorizacionComprobante>
  </soapenv:Body>
</soapenv:Envelope>"""
    try:
        respuesta = _post_soap(SRI[ambiente]["autorizacion"], envelope)
        return jsonify({"estado": "OK", "respuestaSRI": respuesta})
    except Exception as e:
        return _json_error(str(e), 502)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
