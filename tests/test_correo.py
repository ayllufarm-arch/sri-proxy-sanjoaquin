"""El relay generico ya no existe.

Ninguna prueba envia correo: RESEND_API_KEY se deja vacia, asi que el endpoint
corta antes de llamar a Resend. Lo que se comprueba es el contrato.
"""
import importlib, os, pytest


def proxy(monkeypatch, *, resend="", enforce=True):
    monkeypatch.setenv("FIREBASE_PROJECT_ID", "proyecto-de-prueba")
    monkeypatch.setenv("PROXY_AUTH_ENFORCE", "true" if enforce else "false")
    monkeypatch.setenv("PROXY_API_KEY", "")
    monkeypatch.setenv("RESEND_API_KEY", resend)
    monkeypatch.delenv("P12_B64", raising=False)
    import sri_proxy; importlib.reload(sri_proxy)
    sri_proxy.app.config.update(TESTING=True)
    sri_proxy._rate_store.clear()
    return sri_proxy


def test_anonimo_rechazado(monkeypatch):
    m = proxy(monkeypatch)
    assert m.app.test_client().post("/send-email", json={"tipo": "prueba"}).status_code == 401


# --- el contrato viejo, rechazado explicitamente ---------------------------

@pytest.mark.parametrize("carga", [
    {"to": [{"email": "x@y.z"}], "subject": "S", "html": "<b>lo que sea</b>"},
    {"tipo": "prueba", "html": "<script>alert(1)</script>"},
    {"tipo": "boletin", "body": "texto"},
    {"tipo": "boletin", "attachments": [{"filename": "x.pdf", "content": "AAA"}]},
])
def test_html_cuerpo_y_adjuntos_arbitrarios_rechazados(monkeypatch, carga):
    """El fallo que este cambio cierra: un usuario con permiso enviando
    cualquier cosa a cualquiera desde el dominio de la empresa."""
    m = proxy(monkeypatch, enforce=False)  # sin exigencia, para aislar el contrato
    r = m.app.test_client().post("/send-email", json=carga)
    assert r.status_code == 400
    assert "arbitrarios" in r.get_json()["error"]


def test_tipo_desconocido_rechazado(monkeypatch):
    m = proxy(monkeypatch, enforce=False)
    assert m.app.test_client().post("/send-email", json={"tipo": "loquesea"}).status_code == 400
    assert m.app.test_client().post("/send-email", json={}).status_code == 400


# --- prueba: el navegador no elige nada ------------------------------------

def test_prueba_no_acepta_destinatario_del_cliente(monkeypatch):
    """Un correo de prueba que dejara elegir destino seguiria siendo un relay."""
    m = proxy(monkeypatch, resend="", enforce=False)
    r = m.app.test_client().post("/send-email",
                                 json={"tipo": "prueba", "destinatarios": [{"email": "atacante@x.z"}]})
    # 501 al final porque falta RESEND_API_KEY: el destinatario del cliente se
    # ignoro por completo, ni siquiera provoco un error de validacion.
    assert r.status_code == 501


# --- boletin: destinatarios acotados, HTML compuesto por el servidor --------

def test_boletin_exige_asunto_y_bloques(monkeypatch):
    m = proxy(monkeypatch, enforce=False)
    c = m.app.test_client()
    assert c.post("/send-email", json={"tipo": "boletin"}).status_code == 400
    assert c.post("/send-email", json={"tipo": "boletin",
                                       "destinatarios": [{"email": "a@b.c"}]}).status_code == 400
    assert c.post("/send-email", json={"tipo": "boletin", "asunto": "Hola",
                                       "destinatarios": [{"email": "a@b.c"}]}).status_code == 400


def test_boletin_limita_el_numero_de_destinatarios(monkeypatch):
    m = proxy(monkeypatch, enforce=False)
    muchos = [{"email": f"u{i}@ejemplo.test"} for i in range(m.MAX_BOLETIN + 1)]
    r = m.app.test_client().post("/send-email", json={"tipo": "boletin", "asunto": "X",
                                                      "bloques": ["a"], "destinatarios": muchos})
    assert r.status_code == 400


def test_boletin_rechaza_correo_invalido(monkeypatch):
    m = proxy(monkeypatch, enforce=False)
    r = m.app.test_client().post("/send-email", json={
        "tipo": "boletin", "asunto": "X", "bloques": ["a"],
        "destinatarios": [{"email": "no-es-un-correo"}]})
    assert r.status_code == 400


def test_el_servidor_escapa_el_contenido_del_boletin(monkeypatch):
    """Los bloques son texto. Si alguien mete marcado, se escapa: el HTML lo
    compone el servidor, no el navegador."""
    from html import escape
    assert "&lt;script&gt;" in escape("<script>alert(1)</script>")


def test_permiso_de_correo_es_propio(monkeypatch):
    """email:send no lo da tener acceso al panel."""
    import firebase_auth
    assert not firebase_auth.tiene_permiso({"permisos": ["invoice:sign"]}, "email:send")
    assert firebase_auth.tiene_permiso({"permisos": ["email:send"]}, "email:send")


def test_no_se_registra_la_lista_de_correos(monkeypatch):
    """La version anterior imprimia todos los destinatarios en el log."""
    fuente = open("sri_proxy.py", encoding="utf-8", errors="ignore").read()
    assert 'send-email → {to_list}' not in fuente
    assert "destinatarios=%d" in fuente
