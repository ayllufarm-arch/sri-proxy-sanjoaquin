"""Operaciones de pagos: solo el backend de San Joaquín, con su credencial de servicio.

Antes, /payphone/link, /confirm, /status, /confirmed y /button-confirm eran públicos: cualquiera
podía crear enlaces de cobro con el comercio o consultar transacciones (con datos del pagador).
Ahora exigen la cabecera X-SJ-Servicio-Pagos con PROXY_PAGOS_KEY. El webhook sigue público porque
lo llama PayPhone. El token de PayPhone sigue siendo el de Railway (PAYPHONE_TOKEN): no cambia.

Todo es sintético: ninguna prueba llega a PayPhone (requests está sustituido).
"""
import importlib
import logging
import pytest

CLAVE = "clave-servicio-pagos-sintetica-0123456789"
CLAVE_INTERNA = "clave-interna-sintetica-de-mantenimiento-000"
TOKEN_PP = "token-payphone-sintetico-no-real"
DATOS_PAGADOR = "pagador.sintetico@correo.test"

PROTEGIDAS = [
    ("post", "/payphone/link", {"amount": 100, "amountWithTax": 0, "amountWithoutTax": 100, "tax": 0,
                                "currency": "USD", "reference": "SJ-1", "clientTransactionId": "SJ1"}),
    ("post", "/payphone/confirm", {"clientTransactionId": "SJ1"}),
    ("post", "/payphone/status", {"transactionId": "123"}),
    ("get", "/payphone/confirmed/SJ1", None),
    ("post", "/payphone/button-confirm", {"id": 123, "clientTransactionId": "SJ1"}),
]
IDS = [r for _, r, _ in PROTEGIDAS]


class Respuesta:
    def __init__(self, status=200, texto='{"statusCode": 3, "transactionStatus": "Approved", '
                                         '"email": "' + DATOS_PAGADOR + '"}'):
        self.status_code = status
        self.text = texto
        self.headers = {"Content-Type": "application/json"}
        self.content = texto.encode()

    def json(self):
        import json
        return json.loads(self.text)


@pytest.fixture(autouse=True)
def restaurar_modulo():
    """Al terminar, el módulo vuelve a cargarse con el entorno original: estas pruebas no dejan
    su configuración a las siguientes."""
    import os
    from unittest import mock
    entorno = dict(os.environ)
    yield
    import sri_proxy
    with mock.patch.dict(os.environ, entorno, clear=True):
        importlib.reload(sri_proxy)


@pytest.fixture
def llamadas():
    return []


def recargar(monkeypatch, llamadas, *, clave=CLAVE, token=TOKEN_PP, interna=CLAVE_INTERNA, legado=""):
    for nombre, valor in (("PROXY_PAGOS_KEY", clave), ("PAYPHONE_TOKEN", token),
                          ("PROXY_API_KEY", interna), ("LEGACY_PROXY_URL", legado)):
        if valor is None:
            monkeypatch.delenv(nombre, raising=False)
        else:
            monkeypatch.setenv(nombre, valor)
    monkeypatch.setenv("PROXY_AUTH_ENFORCE", "true")
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "proyecto-de-prueba")
    monkeypatch.delenv("P12_B64", raising=False)
    import sri_proxy
    importlib.reload(sri_proxy)
    sri_proxy.app.config.update(TESTING=True)
    sri_proxy._rate_store.clear()
    sri_proxy._confirmed_payments.clear()

    def falso(metodo):
        def llamar(url, *a, **kw):
            llamadas.append({"metodo": metodo, "url": url, **kw})
            if "/api/Links" in url:
                return Respuesta(200, "https://payp.page.link/sintetico")
            return Respuesta()
        return llamar
    monkeypatch.setattr(sri_proxy.requests, "post", falso("POST"))
    monkeypatch.setattr(sri_proxy.requests, "get", falso("GET"))
    monkeypatch.setattr(sri_proxy.requests, "request", lambda metodo, url, *a, **kw: falso(metodo)(url, *a, **kw))
    return sri_proxy


def pedir(cliente, metodo, ruta, cuerpo, cabeceras=None):
    if metodo == "get":
        return cliente.get(ruta, headers=cabeceras or {})
    return cliente.post(ruta, json=cuerpo, headers=cabeceras or {})


# --- sin la credencial de servicio no hay operación ---------------------------

@pytest.mark.parametrize("metodo,ruta,cuerpo", PROTEGIDAS, ids=IDS)
def test_anonimo_rechazado_401_sin_llegar_a_payphone(monkeypatch, llamadas, metodo, ruta, cuerpo):
    m = recargar(monkeypatch, llamadas)
    r = pedir(m.app.test_client(), metodo, ruta, cuerpo)
    assert r.status_code == 401
    assert llamadas == []


@pytest.mark.parametrize("metodo,ruta,cuerpo", PROTEGIDAS, ids=IDS)
def test_credencial_incorrecta_403(monkeypatch, llamadas, metodo, ruta, cuerpo):
    m = recargar(monkeypatch, llamadas)
    r = pedir(m.app.test_client(), metodo, ruta, cuerpo, {"X-SJ-Servicio-Pagos": CLAVE[:-1] + "X"})
    assert r.status_code == 403
    assert llamadas == []


@pytest.mark.parametrize("clave", [None, "", "corta-de-menos-de-32"], ids=["ausente", "vacia", "corta"])
@pytest.mark.parametrize("metodo,ruta,cuerpo", PROTEGIDAS, ids=IDS)
def test_sin_clave_configurada_falla_cerrado_503(monkeypatch, llamadas, metodo, ruta, cuerpo, clave):
    """Una variable ausente no puede volver a abrir los pagos."""
    m = recargar(monkeypatch, llamadas, clave=clave)
    r = pedir(m.app.test_client(), metodo, ruta, cuerpo, {"X-SJ-Servicio-Pagos": clave or "x"})
    assert r.status_code == 503
    assert llamadas == []


@pytest.mark.parametrize("metodo,ruta,cuerpo", PROTEGIDAS, ids=IDS)
def test_con_la_credencial_de_servicio_opera(monkeypatch, llamadas, metodo, ruta, cuerpo):
    m = recargar(monkeypatch, llamadas)
    r = pedir(m.app.test_client(), metodo, ruta, cuerpo, {"X-SJ-Servicio-Pagos": CLAVE})
    assert r.status_code == 200


# --- ninguna otra credencial sirve para pagos -----------------------------------

@pytest.mark.parametrize("metodo,ruta,cuerpo", PROTEGIDAS, ids=IDS)
def test_no_acepta_un_token_de_firebase(monkeypatch, llamadas, metodo, ruta, cuerpo):
    m = recargar(monkeypatch, llamadas)
    r = pedir(m.app.test_client(), metodo, ruta, cuerpo, {"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.e30.x"})
    assert r.status_code == 401
    assert llamadas == []


@pytest.mark.parametrize("metodo,ruta,cuerpo", PROTEGIDAS, ids=IDS)
def test_no_acepta_la_clave_interna_de_mantenimiento(monkeypatch, llamadas, metodo, ruta, cuerpo):
    m = recargar(monkeypatch, llamadas)
    c = m.app.test_client()
    assert pedir(c, metodo, ruta, cuerpo, {"X-Proxy-Key": CLAVE_INTERNA}).status_code == 401
    assert pedir(c, metodo, ruta, cuerpo, {"X-SJ-Servicio-Pagos": CLAVE_INTERNA}).status_code == 403
    assert llamadas == []


def test_no_acepta_la_credencial_por_query_string(monkeypatch, llamadas):
    m = recargar(monkeypatch, llamadas)
    r = m.app.test_client().post(f"/payphone/confirm?X-SJ-Servicio-Pagos={CLAVE}&key={CLAVE}",
                                 json={"clientTransactionId": "SJ1"})
    assert r.status_code == 401


def test_la_credencial_de_pagos_no_abre_la_firma_ni_el_mantenimiento(monkeypatch, llamadas):
    """Autorización por operación: la credencial de pagos solo sirve para pagos."""
    m = recargar(monkeypatch, llamadas)
    c = m.app.test_client()
    assert c.post("/firmar", json={}, headers={"X-SJ-Servicio-Pagos": CLAVE}).status_code == 401
    assert c.get("/cert-info", headers={"X-SJ-Servicio-Pagos": CLAVE}).status_code == 401
    assert c.get("/payphone/debug", headers={"X-SJ-Servicio-Pagos": CLAVE}).status_code == 401
    assert c.get("/payphone/debug", headers={"X-Proxy-Key": CLAVE_INTERNA}).status_code == 200


def test_cada_endpoint_declara_su_operacion():
    import sri_proxy
    assert set(sri_proxy.OPERACIONES_PAGOS) == {"crear_enlace", "consultar", "confirmar"}
    with pytest.raises(ValueError):
        sri_proxy.solo_servicio_pagos("cualquier_cosa")


# --- el token de PayPhone sigue siendo el de Railway --------------------------

def test_usa_el_token_de_railway_e_ignora_el_del_cuerpo(monkeypatch, llamadas):
    m = recargar(monkeypatch, llamadas)
    cuerpo = dict(PROTEGIDAS[0][2], token="token-del-navegador")
    r = m.app.test_client().post("/payphone/link", json=cuerpo, headers={"X-SJ-Servicio-Pagos": CLAVE})
    assert r.status_code == 200 and r.get_data(as_text=True) == "https://payp.page.link/sintetico"
    (llamada,) = llamadas
    assert llamada["headers"]["Authorization"] == f"Bearer {TOKEN_PP}"
    assert "token" not in llamada["json"]
    assert "token-del-navegador" not in repr(llamada)


def test_sin_token_de_payphone_en_el_entorno_no_usa_el_del_cuerpo(monkeypatch, llamadas):
    m = recargar(monkeypatch, llamadas, token="")
    cuerpo = dict(PROTEGIDAS[0][2], token="token-del-navegador")
    r = m.app.test_client().post("/payphone/link", json=cuerpo, headers={"X-SJ-Servicio-Pagos": CLAVE})
    assert r.status_code == 500
    assert llamadas == []


def test_sin_token_no_se_reenvia_al_proxy_legado(monkeypatch, llamadas):
    """El reenvío legado corría antes que la autorización: con PAYPHONE_TOKEN vacío y un proxy
    legado configurado, una petición anónima habría salido sin comprobar nada."""
    m = recargar(monkeypatch, llamadas, token="", legado="https://legado.test")
    for metodo, ruta, cuerpo in PROTEGIDAS:
        assert pedir(m.app.test_client(), metodo, ruta, cuerpo).status_code == 401
    assert llamadas == []


# --- el webhook de PayPhone sigue público y confirma con el token de Railway ----

def test_webhook_get_publico_confirma_y_redirige(monkeypatch, llamadas):
    m = recargar(monkeypatch, llamadas)
    r = m.app.test_client().get("/payphone/webhook?id=123&clientTransactionId=SJ1&paymentId=9")
    assert r.status_code == 302
    (llamada,) = llamadas
    assert "/api/button/Confirm" in llamada["url"]
    assert llamada["headers"]["Authorization"] == f"Bearer {TOKEN_PP}"
    assert m._confirmed_payments["SJ1"]["confirmed"] is True


def test_webhook_post_publico(monkeypatch, llamadas):
    m = recargar(monkeypatch, llamadas)
    r = m.app.test_client().post("/payphone/webhook", json={"clientTransactionId": "SJ1", "statusCode": 3})
    assert r.status_code == 200 and r.get_json() == {"estado": "OK"}


def test_webhook_sin_token_se_puede_reenviar_al_legado(monkeypatch, llamadas):
    """Compatibilidad conservada: solo el webhook (público) se reenvía."""
    m = recargar(monkeypatch, llamadas, token="", legado="https://legado.test")
    m.app.test_client().post("/payphone/webhook", json={"clientTransactionId": "SJ1"})
    assert [l["url"] for l in llamadas] == ["https://legado.test/payphone/webhook"]


# --- navegadores: sin CORS para la cabecera de servicio -------------------------

def test_el_preflight_no_ejecuta_la_operacion_ni_permite_la_cabecera(monkeypatch, llamadas):
    m = recargar(monkeypatch, llamadas)
    r = m.app.test_client().options("/payphone/link", headers={
        "Origin": "https://ejemplo.test", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "x-sj-servicio-pagos, content-type"})
    assert llamadas == []
    assert "x-sj-servicio-pagos" not in r.headers.get("Access-Control-Allow-Headers", "").lower()


# --- registros sin secretos ni datos del pagador ------------------------------

def test_los_registros_no_contienen_credenciales_ni_datos_del_pagador(monkeypatch, llamadas, caplog):
    m = recargar(monkeypatch, llamadas)
    c = m.app.test_client()
    with caplog.at_level(logging.DEBUG):
        for metodo, ruta, cuerpo in PROTEGIDAS:
            pedir(c, metodo, ruta, cuerpo)
            pedir(c, metodo, ruta, cuerpo, {"X-SJ-Servicio-Pagos": "intento-fallido-" + "x" * 30})
            pedir(c, metodo, ruta, cuerpo, {"X-SJ-Servicio-Pagos": CLAVE})
        c.get("/payphone/webhook?id=123&clientTransactionId=SJ1")
        c.post("/payphone/webhook", json={"clientTransactionId": "SJ1", "statusCode": 3, "email": DATOS_PAGADOR})
    for secreto in (CLAVE, TOKEN_PP, CLAVE_INTERNA, "intento-fallido", DATOS_PAGADOR):
        assert secreto not in caplog.text
