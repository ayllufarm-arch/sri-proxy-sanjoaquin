"""Characterization del proxy SRI tal como esta HOY.

Igual que en Firestore: las pruebas marcadas VULNERABILIDAD-ACTUAL describen lo
inseguro que existe, no lo aprueban. Deben fallar cuando entre la correccion.

Ninguna prueba llama al SRI, a PayPhone ni a produccion. El certificado real no
esta cargado (ver conftest).
"""
import json
import pytest
import sri_proxy


# --------------------------------------------------------------------------
# Salud y configuracion
# --------------------------------------------------------------------------

def test_health_responde_200(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_CORREGIDO_health_ya_no_publica_configuracion(client):
    """Antes /health publicaba la lista de origenes y el correo del
    administrador sin pedir credencial. Ya no.

    `p12_en_servidor` se conserva a proposito: la operacion lo consulta para
    saber si el servicio puede firmar, y no revela nada que un atacante no
    averigue igual intentandolo.
    """
    d = client.get("/health").get_json()
    assert "cors_origin" not in d
    assert "admin_email" not in d
    assert d["status"] == "ok"


def test_firma_no_disponible_se_degrada_sin_romper(client):
    """Si faltan los modulos de firma, el servicio arranca igual y avisa."""
    assert isinstance(sri_proxy.FIRMA_DISPONIBLE, bool)


# --------------------------------------------------------------------------
# /firmar — el P0
# --------------------------------------------------------------------------

def test_VULNERABILIDAD_ACTUAL_firmar_no_pide_credencial(client):
    """POST /firmar sin ninguna credencial NO es rechazado por autenticacion.

    Se envia un cuerpo vacio a proposito: la respuesta es un error de validacion
    (falta xmlBase64) o de modulos de firma, NUNCA 401 ni 403. Es decir, la
    peticion llega al manejador. Con P12_B64 configurado -- como esta en
    produccion -- el siguiente paso seria firmar.

    No se envia XML real. No se provoca ninguna firma.

    Al corregir: esta prueba debe devolver 401.
    """
    r = client.post("/firmar", json={})
    assert r.status_code not in (401, 403), (
        "si ahora devuelve 401/403, la autenticacion ya entro: actualiza esta prueba"
    )
    assert r.status_code in (400, 501)


def test_VULNERABILIDAD_ACTUAL_origen_ajeno_no_bloquea_al_servidor(client):
    """CORS no protege al servidor.

    Una peticion con un Origin que no esta en la lista blanca llega igual al
    manejador. CORS solo instruye al navegador; un cliente que no sea navegador
    lo ignora.
    """
    r = client.post("/firmar", json={}, headers={"Origin": "https://atacante.test"})
    assert r.status_code not in (401, 403)


def test_firmar_valida_que_falte_el_xml(client):
    r = client.post("/firmar", json={})
    assert r.status_code in (400, 501)


# --------------------------------------------------------------------------
# Endpoints de depuracion
# --------------------------------------------------------------------------

def test_VULNERABILIDAD_ACTUAL_debug_accesible_sin_credencial(client):
    """/payphone/debug responde sin autenticacion.

    Al corregir: debe desaparecer en produccion o exigir credencial.
    """
    r = client.get("/payphone/debug")
    assert r.status_code not in (401, 403, 404)


def test_VULNERABILIDAD_ACTUAL_cert_info_accesible_sin_credencial(client):
    """/cert-info publica sujeto, emisor, serie y vigencia del certificado."""
    r = client.get("/cert-info")
    assert r.status_code not in (401, 403)


# --------------------------------------------------------------------------
# Estado en memoria e idempotencia
# --------------------------------------------------------------------------

def test_VULNERABILIDAD_ACTUAL_estado_de_pagos_vive_en_memoria(client):
    """`_token_store` es un dict de modulo.

    Con --workers 2, lo que guarda un worker no existe para el otro, y un
    reinicio lo pierde entero. Afecta a la confirmacion de pagos.

    Al corregir: el estado debe persistirse fuera del proceso.
    """
    assert isinstance(sri_proxy._token_store, dict)
    sri_proxy._token_store["tx-sintetico"] = {"token": "x", "timestamp": 0}
    assert "tx-sintetico" in sri_proxy._token_store
    sri_proxy._token_store.pop("tx-sintetico")


def test_VULNERABILIDAD_ACTUAL_rate_limit_es_por_proceso(client):
    """El rate limit tambien es un dict de modulo: es por worker.

    Con dos workers el limite efectivo es el doble del configurado, y no
    sobrevive a un reinicio. Sirve como freno, no como autorizacion.
    """
    assert isinstance(sri_proxy._rate_store, dict)
    assert sri_proxy.RATE_LIMIT > 0


def test_VULNERABILIDAD_ACTUAL_sin_idempotencia_en_emision(client):
    """No hay registro de claves de acceso emitidas.

    Dos envios del mismo comprobante -- un reintento, un doble clic -- llegan al
    SRI dos veces. El codigo valida la FORMA de claveAcceso, no si ya se uso.
    """
    fuente = open("sri_proxy.py", encoding="utf-8", errors="ignore").read()
    assert "idempot" not in fuente.lower(), "si ya hay idempotencia, actualiza esta prueba"


def test_autorizacion_valida_la_forma_de_clave_acceso(client):
    """Lo que SI valida: 49 digitos numericos. Esto debe seguir funcionando."""
    r = client.post("/autorizacion", json={"claveAcceso": "123"})
    assert r.status_code == 400
    r = client.post("/autorizacion", json={})
    assert r.status_code == 400


# ── CORS y la cabecera Authorization ─────────────────────────────────────────
# El 14-sep-2026, al unificar el hosting, produccion paso a servir el admin.html
# que manda el ID token de Firebase en cada llamada fiscal. La config de CORS
# solo permitia Content-Type, asi que el navegador bloqueaba la peticion en el
# preflight: no es que el proxy respondiera mal, es que la peticion no llegaba a
# salir. Estas pruebas impiden que vuelva a ocurrir.

def test_preflight_permite_authorization(client):
    """Sin esto, proxyFetch no puede hablar con el proxy desde el navegador."""
    r = client.open("/firmar", method="OPTIONS", headers={
        "Origin": "https://ejemplo.test",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    })
    permitidas = (r.headers.get("Access-Control-Allow-Headers") or "").lower()
    assert "authorization" in permitidas, \
        f"el preflight no permite Authorization: {permitidas!r}"
    assert "content-type" in permitidas


def test_el_401_llega_con_cabeceras_cors(client):
    """Un 401 sin Access-Control-Allow-Origin le llega al navegador como error de
    red, no como 401: proxyFetch no podria distinguir sesion caducada de caida
    del servicio."""
    r = client.post("/firmar", json={}, headers={"Origin": "https://ejemplo.test"})
    assert r.headers.get("Access-Control-Allow-Origin") == "https://ejemplo.test"
