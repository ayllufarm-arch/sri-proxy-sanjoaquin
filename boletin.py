"""Plantilla del boletin, del lado del servidor.

Antes la construia el navegador y la mandaba como HTML libre. Eso convertia
/send-email en un relay: quien tuviera permiso podia enviar cualquier marcado a
cualquiera desde el dominio de la empresa.

Ahora el navegador manda datos -- tipo de campana, nombre, precio -- y el
servidor compone el correo. La apariencia se conserva: mismo esqueleto de tabla,
mismos colores de marca, misma tarjeta de producto, mismo boton y mismo pie con
la baja de suscripcion. Lo que cambia es quien decide el marcado.

Todo texto que venga de fuera se escapa antes de entrar en el HTML.
"""

from html import escape
from urllib.parse import urlparse

MARCA = "#8B0000"
MAX_PRODUCTOS = 20
TIPOS = ("nueva_produccion", "nuevo_producto", "promocion")


class DatosInvalidos(ValueError):
    """El cuerpo no cumple el contrato. El mensaje se devuelve al cliente."""


def _url_segura(valor, campo):
    """Solo http/https. Un `javascript:` en un boton es ejecucion en el correo
    del suscriptor, y `data:` permite incrustar contenido arbitrario."""
    texto = str(valor or "").strip()
    if not texto:
        raise DatosInvalidos(f"{campo} es obligatorio")
    if len(texto) > 500:
        raise DatosInvalidos(f"{campo} demasiado largo")
    p = urlparse(texto)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise DatosInvalidos(f"{campo} debe ser una URL http o https")
    return texto


def _texto(valor, campo, maximo=200, obligatorio=True):
    t = str(valor or "").strip()
    if not t and obligatorio:
        raise DatosInvalidos(f"{campo} es obligatorio")
    if len(t) > maximo:
        raise DatosInvalidos(f"{campo} supera {maximo} caracteres")
    return t


def _precio(valor):
    if valor in (None, ""):
        return None
    try:
        n = float(valor)
    except (TypeError, ValueError):
        raise DatosInvalidos("precio no es un numero")
    if n < 0 or n > 100000:
        raise DatosInvalidos("precio fuera de rango")
    return f"{n:.2f}"


def asunto_de(tipo, datos):
    """El asunto lo decide el servidor: es parte de la plantilla, no del cuerpo
    de la peticion."""
    if tipo == "nueva_produccion":
        return "Nueva produccion disponible - San Joaquin"
    if tipo == "nuevo_producto":
        nombre = _texto(datos.get("nombre"), "nombre", 80)
        return f"Nuevo producto: {nombre} - San Joaquin"
    return "Novedades - San Joaquin"


def _boton(url, texto):
    return (f'<div style="text-align:center;margin:24px 0 8px">'
            f'<a href="{escape(url)}" style="display:inline-block;background:{MARCA};'
            f'color:#fff;text-decoration:none;padding:13px 32px;border-radius:6px;'
            f'font-size:15px;font-weight:700;letter-spacing:0.3px">{escape(texto)}</a></div>')


def _cuerpo(tipo, datos, tienda):
    if tipo == "nueva_produccion":
        productos = _texto(datos.get("productos"), "productos", 400)
        caja = (f'<div style="background:#fdf5f5;border-left:4px solid {MARCA};'
                f'border-radius:4px;padding:14px 16px;margin:16px 0">'
                f'<div style="font-size:13px;color:{MARCA};font-weight:700;margin-bottom:6px;'
                f'text-transform:uppercase;letter-spacing:0.5px">Productos disponibles</div>'
                f'<div style="color:#333;font-size:15px;font-weight:600">'
                f'{escape(productos)}</div></div>')
        return ('<p style="margin:0 0 14px;font-size:16px">Ya tenemos '
                '<strong>nueva produccion lista</strong> fresca para esta temporada.</p>'
                + caja
                + '<p style="margin:0 0 4px;color:#666;font-size:14px">'
                  'Haz tu pedido antes de que se agote.</p>'
                + _boton(tienda, "Ver tienda y pedir ahora"))

    if tipo == "nuevo_producto":
        nombre = _texto(datos.get("nombre"), "nombre", 80)
        precio = _precio(datos.get("precio"))
        bloque_precio = (f'<div style="font-size:14px;color:#666;margin-top:4px">Desde '
                         f'<strong style="color:{MARCA};font-size:16px">${precio}</strong>'
                         f' / kg</div>') if precio else ""
        return ('<p style="margin:0 0 20px;font-size:16px">Acabamos de incorporar un '
                'nuevo producto a nuestra linea artesanal.</p>'
                f'<div style="background:#fdf5f5;border-radius:8px;padding:20px;'
                f'text-align:center;margin-bottom:20px">'
                f'<div style="font-size:22px;font-weight:700;color:{MARCA};'
                f'margin-bottom:4px">{escape(nombre)}</div>{bloque_precio}</div>'
                + _boton(tienda, "Verlo en la tienda"))

    mensaje = _texto(datos.get("mensaje"), "mensaje", 600)
    return (f'<p style="margin:0 0 18px;font-size:16px">{escape(mensaje)}</p>'
            + _boton(tienda, "Ver la tienda"))


def render(tipo, datos, tienda_url):
    """Devuelve (asunto, html). Levanta DatosInvalidos si el cuerpo no cumple."""
    if tipo not in TIPOS:
        raise DatosInvalidos(f"tipo debe ser uno de {', '.join(TIPOS)}")
    if not isinstance(datos, dict):
        raise DatosInvalidos("datos debe ser un objeto")
    if len(datos) > 12:
        raise DatosInvalidos("demasiados campos en datos")
    tienda = _url_segura(datos.get("tiendaUrl") or tienda_url, "tiendaUrl")

    asunto = asunto_de(tipo, datos)
    cuerpo = _cuerpo(tipo, datos, tienda)

    html = (
        '<table width="100%" cellpadding="0" cellspacing="0" '
        'style="background:#f0ebe8;padding:24px 0"><tr><td align="center">'
        '<table width="100%" style="max-width:560px;background:#ffffff;'
        'border-radius:10px;overflow:hidden;font-family:Arial,Helvetica,sans-serif">'
        f'<tr><td style="background:{MARCA};padding:22px 24px">'
        '<div style="color:#fff;font-size:22px;font-weight:800;letter-spacing:0.5px">'
        'SAN JOAQUIN</div>'
        '<div style="color:#f5c5c5;font-size:12px;letter-spacing:2px;margin-top:4px">'
        'ARTESANIA CARNICA</div></td></tr>'
        f'<tr><td style="padding:24px">{cuerpo}</td></tr>'
        '<tr><td style="padding:16px 24px 24px;border-top:1px solid #eee;text-align:center">'
        f'<a href="{escape(tienda)}" style="color:{MARCA};font-size:13px;'
        'font-weight:600;text-decoration:none">sanjoaquinartesaniacarnica.com</a>'
        '<div style="font-size:11px;color:#aaa;margin-top:8px">'
        f'<a href="{escape(tienda)}#unsub" style="color:#bbb">Darse de baja</a>'
        '</div></td></tr></table></td></tr></table>')
    return asunto, html


def suscriptores(project_id, id_token, limite=500):
    """Lee la coleccion `newsletter` con el token del PROPIO usuario.

    La API REST de Firestore acepta un ID token de Firebase como Bearer y, a
    diferencia de una cuenta de servicio, **aplica las reglas de seguridad**. La
    documentacion oficial lo dice asi: con un ID token "Cloud Firestore usa las
    reglas de seguridad para determinar si la peticion esta autorizada", mientras
    que una cuenta de servicio "permite a estas peticiones ignorar tus reglas".

    Por eso esta es la opcion correcta y no hace falta credencial nueva: el proxy
    no obtiene mas acceso del que ya tiene quien llama. Si un dia se restringe la
    lectura de `newsletter`, esto deja de funcionar solo, que es lo deseable.
    """
    import requests

    url = (f"https://firestore.googleapis.com/v1/projects/{project_id}"
           f"/databases/(default)/documents/newsletter?pageSize={min(limite, 300)}")
    correos, pagina = [], None
    while True:
        r = requests.get(url + (f"&pageToken={pagina}" if pagina else ""),
                         headers={"Authorization": f"Bearer {id_token}"}, timeout=15)
        if r.status_code == 403:
            raise PermissionError("Las reglas de Firestore no permiten leer la lista")
        r.raise_for_status()
        cuerpo = r.json()
        for doc in cuerpo.get("documents", []):
            campos = doc.get("fields", {})
            correo = (campos.get("email", {}).get("stringValue") or "").strip().lower()
            if "@" in correo and len(correo) <= 254:
                correos.append(correo)
        pagina = cuerpo.get("nextPageToken")
        if not pagina or len(correos) >= limite:
            break
    # Deduplicado preservando el orden de llegada.
    vistos, unicos = set(), []
    for c in correos:
        if c not in vistos:
            vistos.add(c)
            unicos.append(c)
    return unicos[:limite]
