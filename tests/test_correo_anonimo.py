"""/enviar-codigo y /verificar-codigo: ya no son anónimos.

Eran del alta de cuentas desde el navegador, que la web ya no tiene. Una petición anónima a
/enviar-codigo hacía enviar un correo real a administración (comprobado el 28/09/2026), y el límite
por IP se eludía con X-Forwarded-For. Ahora exigen PROXY_API_KEY y fallan cerrados sin ella.

Todo es sintético: ni Resend ni SMTP (requests y smtplib están sustituidos).
"""
import importlib
import logging
import pytest

CLAVE_INTERNA = "clave-interna-sintetica-de-mantenimiento-000"
RUTAS = ["/enviar-codigo", "/verificar-codigo"]


@pytest.fixture(autouse=True)
def restaurar_modulo():
    import os
    from unittest import mock
    entorno = dict(os.environ)
    yield
    import sri_proxy
    with mock.patch.dict(os.environ, entorno, clear=True):
        importlib.reload(sri_proxy)


@pytest.fixture
def envios():
    return []


def recargar(monkeypatch, envios, *, interna="", resend="re_sintetica_no_real", legado=""):
    for nombre, valor in (("PROXY_API_KEY", interna), ("RESEND_API_KEY", resend), ("LEGACY_PROXY_URL", legado),
                          ("ADMIN_EMAIL", "administracion@ejemplo.test")):
        monkeypatch.setenv(nombre, valor)
    monkeypatch.delenv("GMAIL_USER", raising=False)
    monkeypatch.delenv("GMAIL_APP_PASSWORD", raising=False)
    monkeypatch.setenv("PROXY_AUTH_ENFORCE", "true")
    monkeypatch.delenv("P12_B64", raising=False)
    import sri_proxy
    importlib.reload(sri_proxy)
    sri_proxy.app.config.update(TESTING=True)
    sri_proxy._rate_store.clear()
    sri_proxy._verification_codes.clear()

    class Respuesta:
        status_code = 200
        text = '{"id":"sintetico"}'
        content = text.encode()
        headers = {"Content-Type": "application/json"}

    def registrar(*a, **k):
        envios.append((a, k))
        return Respuesta()
    monkeypatch.setattr(sri_proxy.requests, "post", registrar)
    monkeypatch.setattr(sri_proxy.requests, "request", registrar)
    monkeypatch.setattr(sri_proxy.smtplib, "SMTP_SSL", lambda *a, **k: pytest.fail("no debe usar SMTP"), raising=False)
    return sri_proxy


@pytest.mark.parametrize("ruta", RUTAS)
def test_anonimo_sin_clave_configurada_falla_cerrado_y_no_envia(monkeypatch, envios, ruta):
    """Así queda en producción: PROXY_API_KEY no está configurada."""
    m = recargar(monkeypatch, envios)
    r = m.app.test_client().post(ruta, json={"motivo": "primer-admin", "codigo": "123456"})
    assert r.status_code == 503
    assert envios == []
    assert m._verification_codes == {}


@pytest.mark.parametrize("ruta", RUTAS)
def test_anonimo_con_clave_configurada_401(monkeypatch, envios, ruta):
    m = recargar(monkeypatch, envios, interna=CLAVE_INTERNA)
    c = m.app.test_client()
    assert c.post(ruta, json={}).status_code == 401
    assert c.post(ruta, json={}, headers={"X-Proxy-Key": "otra"}).status_code == 401
    assert c.post(ruta, json={}, headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.e30.x"}).status_code == 401
    assert envios == []


def test_eludir_el_limite_con_x_forwarded_for_no_sirve(monkeypatch, envios):
    m = recargar(monkeypatch, envios)
    c = m.app.test_client()
    for i in range(30):
        assert c.post("/enviar-codigo", json={}, headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code == 503
    assert envios == []


def test_el_preflight_no_envia_nada(monkeypatch, envios):
    m = recargar(monkeypatch, envios)
    m.app.test_client().options("/enviar-codigo", headers={"Origin": "https://ejemplo.test", "Access-Control-Request-Method": "POST"})
    assert envios == []


def test_no_se_reenvia_al_proxy_legado(monkeypatch, envios):
    """Antes, sin correo configurado y con proxy legado, se reenviaba ANTES de cualquier comprobación."""
    m = recargar(monkeypatch, envios, resend="", legado="https://legado.test")
    for ruta in RUTAS:
        assert m.app.test_client().post(ruta, json={}).status_code == 503
    assert envios == []


def test_mantenimiento_con_la_clave_interna_sigue_funcionando(monkeypatch, envios):
    """Uso interno explícito (no anónimo): la función no se pierde si algún día se necesita."""
    m = recargar(monkeypatch, envios, interna=CLAVE_INTERNA)
    c = m.app.test_client()
    r = c.post("/enviar-codigo", json={"motivo": "primer-admin"}, headers={"X-Proxy-Key": CLAVE_INTERNA})
    assert r.status_code == 200 and len(envios) == 1
    codigo = m._verification_codes["administracion@ejemplo.test"]["code"]
    assert c.post("/verificar-codigo", json={"codigo": codigo}, headers={"X-Proxy-Key": CLAVE_INTERNA}).get_json() == {"estado": "OK"}


def test_los_registros_no_contienen_la_clave_interna_ni_codigos(monkeypatch, envios, caplog):
    m = recargar(monkeypatch, envios, interna=CLAVE_INTERNA)
    with caplog.at_level(logging.DEBUG):
        m.app.test_client().post("/enviar-codigo", json={}, headers={"X-Proxy-Key": "intento-fallido"})
        m.app.test_client().post("/verificar-codigo", json={"codigo": "654321"})
    assert CLAVE_INTERNA not in caplog.text and "intento-fallido" not in caplog.text and "654321" not in caplog.text


def test_ninguna_ruta_que_envie_correo_queda_anonima():
    """Inventario: toda ruta cuyo manejador puede enviar correo exige identidad o la clave interna."""
    import inspect
    import sri_proxy
    for regla in sri_proxy.app.url_map.iter_rules():
        vista = sri_proxy.app.view_functions[regla.endpoint]
        fuente = inspect.getsource(inspect.unwrap(vista))
        if any(s in fuente for s in ("send_verification_email", "api.resend.com", "smtplib")):
            envoltorios = inspect.getsource(sri_proxy).split(f"def {inspect.unwrap(vista).__name__}(")[0].rsplit("@app.route", 1)[1]
            assert "@solo_interno" in envoltorios or "@requiere_identidad" in envoltorios, regla.rule
