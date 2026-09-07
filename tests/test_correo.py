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

def test_boletin_exige_campana_valida(monkeypatch):
    m = proxy(monkeypatch, enforce=False)
    c = m.app.test_client()
    assert c.post("/send-email", json={"tipo": "boletin"}).status_code == 400
    assert c.post("/send-email", json={"tipo": "boletin",
                                       "campana": "inventada"}).status_code == 400


def test_boletin_ya_no_acepta_destinatarios_del_navegador(monkeypatch):
    """El cambio de fondo: el navegador ya no elige a quien se escribe.

    Mandar destinatarios no sirve de nada -- se ignoran -- y sin token la
    peticion no puede leer la lista, asi que se corta antes de enviar.
    """
    m = proxy(monkeypatch, enforce=False)
    r = m.app.test_client().post("/send-email", json={
        "tipo": "boletin", "campana": "nueva_produccion",
        "datos": {"productos": "Chorizo"},
        "destinatarios": [{"email": "atacante@ejemplo.test"}]})
    assert r.status_code == 401
    assert "identidad" in r.get_json()["error"]


def test_boletin_ya_no_acepta_asunto_del_navegador(monkeypatch):
    """El asunto es parte de la plantilla del servidor."""
    import boletin
    a, _ = boletin.render("nueva_produccion", {"productos": "Chorizo"}, "https://ejemplo.test")
    assert a == "Nueva produccion disponible - San Joaquin"


def test_la_plantilla_escapa_el_contenido(monkeypatch):
    import boletin
    _, html = boletin.render("nuevo_producto",
                             {"nombre": "<script>alert(1)</script>"}, "https://e.test")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("mala", ["javascript:alert(1)", "data:text/html,x", "ftp://x.y"])
def test_la_plantilla_rechaza_urls_peligrosas(mala):
    """Un javascript: en el boton es ejecucion en el correo del suscriptor."""
    import boletin
    with pytest.raises(boletin.DatosInvalidos):
        boletin.render("promocion", {"mensaje": "x", "tiendaUrl": mala}, "https://e.test")


def test_la_plantilla_conserva_la_apariencia():
    """Paridad visual: tarjeta de producto, precio, boton, marca y baja."""
    import boletin
    _, html = boletin.render("nuevo_producto",
                             {"nombre": "Chorizo ahumado", "precio": "12.5"},
                             "https://ejemplo.test")
    for pieza in ["SAN JOAQUIN", "ARTESANIA CARNICA", "Chorizo ahumado",
                  "$12.50", "Verlo en la tienda", "Darse de baja", "#8B0000"]:
        assert pieza in html, pieza


def test_la_plantilla_limita_longitudes():
    import boletin
    with pytest.raises(boletin.DatosInvalidos):
        boletin.render("nuevo_producto", {"nombre": "x" * 200}, "https://e.test")
    with pytest.raises(boletin.DatosInvalidos):
        boletin.render("nuevo_producto", {"nombre": "x", "precio": "999999"}, "https://e.test")


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
