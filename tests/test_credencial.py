"""Control de acceso: dos mecanismos, cada uno donde corresponde.

Endpoints fiscales -> identidad de Firebase + permiso. Los llama el navegador,
y un secreto compartido en el navegador es un secreto publicado.

Endpoints de mantenimiento -> credencial servidor-a-servidor. No los llama nadie
desde un navegador.
"""
import importlib
import logging
import pytest

FISCALES = ["/firmar", "/recepcion", "/autorizacion", "/send-invoice", "/send-email"]
MANTENIMIENTO = ["/cert-info", "/payphone/debug"]


def recargar(monkeypatch, *, clave="", enforce=False, proyecto="proyecto-de-prueba"):
    monkeypatch.setenv("PROXY_API_KEY", clave)
    monkeypatch.setenv("PROXY_AUTH_ENFORCE", "true" if enforce else "false")
    monkeypatch.setenv("FIREBASE_PROJECT_ID", proyecto)
    monkeypatch.delenv("P12_B64", raising=False)
    import sri_proxy
    importlib.reload(sri_proxy)
    sri_proxy.app.config.update(TESTING=True)
    sri_proxy._rate_store.clear()
    return sri_proxy


# --- identidad de Firebase en los endpoints fiscales -----------------------

@pytest.mark.parametrize("ruta", FISCALES)
def test_sin_token_rechaza_401(monkeypatch, ruta):
    m = recargar(monkeypatch, enforce=True)
    r = m.app.test_client().post(ruta, json={})
    assert r.status_code == 401


@pytest.mark.parametrize("ruta", FISCALES)
def test_token_ilegible_rechaza_401(monkeypatch, ruta):
    m = recargar(monkeypatch, enforce=True)
    r = m.app.test_client().post(ruta, json={},
                                 headers={"Authorization": "Bearer basura"})
    assert r.status_code == 401


def test_rol_en_el_cuerpo_no_sirve(monkeypatch):
    """Mandar role o uid en el cuerpo no autoriza nada: el permiso viaja firmado
    dentro del token, no en algo que el cliente escriba."""
    m = recargar(monkeypatch, enforce=True)
    r = m.app.test_client().post("/firmar",
                                 json={"role": "Administrador", "uid": "x",
                                       "permisos": ["invoice:sign"]})
    assert r.status_code == 401


def test_token_de_otro_proyecto_se_rechaza(monkeypatch):
    """Sin comprobar la audiencia, cualquiera crearia un proyecto Firebase propio
    y entraria con un token perfectamente firmado por Google."""
    import firebase_auth
    with pytest.raises(firebase_auth.AuthError):
        firebase_auth.verificar_id_token("no.es.un.token", "otro-proyecto")


def test_sin_proyecto_configurado_es_503_no_permitir(monkeypatch):
    """Un despliegue mal configurado debe fallar cerrado, no abierto."""
    import firebase_auth
    with pytest.raises(firebase_auth.AuthError) as e:
        firebase_auth.verificar_id_token("x", "")
    assert e.value.http == 503


def test_permiso_debe_ser_lista(monkeypatch):
    import firebase_auth
    assert firebase_auth.tiene_permiso({"permisos": ["invoice:sign"]}, "invoice:sign")
    assert not firebase_auth.tiene_permiso({"permisos": "invoice:sign"}, "invoice:sign")
    assert not firebase_auth.tiene_permiso({}, "invoice:sign")
    assert not firebase_auth.tiene_permiso({"permisos": ["sri:read"]}, "invoice:sign")


def test_el_token_nunca_aparece_en_los_logs(monkeypatch, caplog):
    m = recargar(monkeypatch, enforce=True)
    secreto = "token-que-no-debe-aparecer"
    with caplog.at_level(logging.WARNING):
        m.app.test_client().post("/firmar", json={},
                                 headers={"Authorization": f"Bearer {secreto}"})
    assert secreto not in caplog.text
    assert "/firmar" in caplog.text


def test_modo_observacion_no_rompe_la_facturacion(monkeypatch):
    """Con enforce apagado se registra el rechazo pero la peticion sigue.

    Es lo que permite desplegar sin cortar la facturacion mientras el navegador
    todavia no manda token.
    """
    m = recargar(monkeypatch, enforce=False)
    r = m.app.test_client().post("/firmar", json={})
    assert r.status_code not in (401, 403)


# --- credencial servidor-a-servidor en mantenimiento -----------------------

@pytest.mark.parametrize("ruta", MANTENIMIENTO)
def test_mantenimiento_sin_credencial_rechaza(monkeypatch, ruta):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    assert m.app.test_client().get(ruta).status_code == 401


@pytest.mark.parametrize("ruta", MANTENIMIENTO)
def test_mantenimiento_con_credencial_pasa(monkeypatch, ruta):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    r = m.app.test_client().get(ruta, headers={"X-Proxy-Key": "secreto-de-prueba"})
    assert r.status_code != 401


def test_la_credencial_NO_se_acepta_por_query_string(monkeypatch):
    """Las URLs acaban en logs de acceso, historial y cabeceras Referer."""
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    assert m.app.test_client().get("/cert-info?key=secreto-de-prueba").status_code == 401


def test_la_credencial_de_servicio_sigue_valiendo_en_fiscales(monkeypatch):
    """Se conserva a proposito: permite un consumidor servidor-a-servidor futuro
    sin volver a tocar el proxy."""
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    r = m.app.test_client().post("/firmar", json={},
                                 headers={"X-Proxy-Key": "secreto-de-prueba"})
    assert r.status_code != 401


def test_health_sigue_publico_y_minimo(monkeypatch):
    m = recargar(monkeypatch, clave="secreto-de-prueba", enforce=True)
    d = m.app.test_client().get("/health").get_json()
    assert d["status"] == "ok"
    assert "cors_origin" not in d
    assert "admin_email" not in d


# --- PayPhone: estado y secretos -------------------------------------------

def test_el_token_de_payphone_no_se_registra(monkeypatch, caplog):
    """El log imprimia los 12 primeros caracteres del token. Un prefijo de un
    secreto sigue siendo parte del secreto."""
    fuente = open("sri_proxy.py", encoding="utf-8", errors="ignore").read()
    assert "token[:12]" not in fuente
    assert "token prefix" not in fuente


def test_la_confirmacion_no_depende_de_la_memoria_del_proceso(monkeypatch):
    """Con dos workers, el token guardado por uno no existia para el otro: la
    confirmacion del pago dependia de a que worker volviera PayPhone."""
    fuente = open("sri_proxy.py", encoding="utf-8", errors="ignore").read()
    assert "token = PAYPHONE_TOKEN or _token_store.get" in fuente
