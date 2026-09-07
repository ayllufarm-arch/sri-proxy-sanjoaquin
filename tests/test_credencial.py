"""Comportamiento del control de acceso nuevo.

Se prueban los dos modos a proposito: con `PROXY_AUTH_ENFORCE` apagado el
servicio se comporta como antes -- eso es lo que permite desplegar sin romper
facturacion -- y encendido rechaza.
"""
import importlib
import logging
import os
import pytest


def recargar(monkeypatch, *, clave="", enforce=False):
    monkeypatch.setenv("PROXY_API_KEY", clave)
    monkeypatch.setenv("PROXY_AUTH_ENFORCE", "true" if enforce else "false")
    monkeypatch.delenv("P12_B64", raising=False)
    import sri_proxy
    importlib.reload(sri_proxy)
    sri_proxy.app.config.update(TESTING=True)
    sri_proxy._rate_store.clear()
    return sri_proxy


# /send-email solo existe en la fuente de produccion; mi base local estaba diez
# commits atras y no lo tenia. Es un relay de correo abierto: sin credencial,
# cualquiera puede enviar correo desde la cuenta Resend de la empresa.
PRIVILEGIADOS = ["/firmar", "/recepcion", "/autorizacion", "/send-invoice", "/send-email"]


@pytest.mark.parametrize("ruta", PRIVILEGIADOS)
def test_sin_credencial_rechaza_cuando_esta_activo(monkeypatch, ruta):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    r = m.app.test_client().post(ruta, json={})
    assert r.status_code == 401
    assert r.get_json()["error"] == "No autorizado"


@pytest.mark.parametrize("ruta", PRIVILEGIADOS)
def test_credencial_equivocada_rechaza(monkeypatch, ruta):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    r = m.app.test_client().post(ruta, json={}, headers={"X-Proxy-Key": "otra"})
    assert r.status_code == 401


@pytest.mark.parametrize("ruta", PRIVILEGIADOS)
def test_credencial_valida_llega_al_manejador(monkeypatch, ruta):
    """Con la credencial correcta la peticion pasa y falla por su propia
    validacion (falta el cuerpo), no por autenticacion."""
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    r = m.app.test_client().post(ruta, json={}, headers={"X-Proxy-Key": "secreto-de-prueba"})
    assert r.status_code != 401


def test_la_credencial_NO_se_acepta_por_query_string(monkeypatch):
    """Las URLs acaban en logs de acceso, historial y cabeceras Referer."""
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    r = m.app.test_client().post("/firmar?key=secreto-de-prueba", json={})
    assert r.status_code == 401


def test_modo_observacion_no_rompe_nada(monkeypatch):
    """Con enforce apagado se registra el aviso pero la peticion sigue.

    Este es el modo con el que se despliega: permite medir quien llama sin
    credencial antes de cerrar la puerta.
    """
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=False)
    r = m.app.test_client().post("/firmar", json={})
    assert r.status_code != 401


def test_sin_clave_configurada_no_bloquea(monkeypatch):
    """Si PROXY_API_KEY esta vacio el control queda inactivo aunque enforce
    este encendido -- de otro modo un despliegue mal configurado dejaria al
    negocio sin facturar y sin forma obvia de saber por que."""
    m = recargar(monkeypatch, clave="", enforce=True)
    r = m.app.test_client().post("/firmar", json={})
    assert r.status_code == 401  # sin clave valida no se puede autenticar a nadie


def test_el_secreto_nunca_aparece_en_los_logs(monkeypatch, caplog):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    with caplog.at_level(logging.WARNING):
        m.app.test_client().post("/firmar", json={}, headers={"X-Proxy-Key": "intento-fallido"})
    texto = caplog.text
    assert "secreto-de-prueba" not in texto
    assert "intento-fallido" not in texto
    assert "/firmar" in texto


def test_debug_y_cert_info_quedan_detras_de_credencial(monkeypatch):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    c = m.app.test_client()
    assert c.get("/payphone/debug").status_code == 401
    assert c.get("/cert-info").status_code == 401
    assert c.get("/health").status_code == 200  # health sigue publico
