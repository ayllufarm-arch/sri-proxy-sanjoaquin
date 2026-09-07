"""Idempotencia fiscal por clave de acceso del SRI.

Un comprobante ya tiene identidad unica: su clave de acceso de 49 digitos. No
hace falta inventar otra, y hacerlo seria peor -- dos identidades para la misma
factura acaban discrepando.

Reglas:
  misma clave + mismo documento  -> se devuelve el resultado anterior
  misma clave + documento distinto -> conflicto, no se envia
  clave en curso                 -> conflicto, no se procesa en paralelo

El almacen es un dict con lock. Vive en el proceso, igual que antes, y eso NO
resuelve el caso de dos workers: dos peticiones simultaneas que caigan en
workers distintos siguen pudiendo pasar. Se documenta en vez de disimularlo,
porque la solucion real es un almacen compartido y eso es infraestructura que
todavia no esta autorizada. Aun asi cubre el caso frecuente -- el doble clic y
el reintento del navegador, que van al mismo worker por keep-alive -- y deja el
contrato escrito para cuando haya donde persistirlo.
"""

import hashlib
import threading
import time

TTL = 24 * 3600

_lock = threading.Lock()
_registro = {}


class Conflicto(Exception):
    """Misma clave de acceso, distinto documento, o envio en curso."""


def huella(xml_bytes):
    """Identidad del documento.

    Se calcula sobre los bytes exactos que se van a enviar. No se normaliza el
    XML: canonicalizarlo aqui significaria alterar lo que se firma, y un
    comprobante firmado no se toca. Dos representaciones distintas del mismo
    comprobante se tratan como documentos distintos, que es el lado seguro del
    error.
    """
    if isinstance(xml_bytes, str):
        xml_bytes = xml_bytes.encode("utf-8")
    return hashlib.sha256(xml_bytes).hexdigest()


def _purgar(ahora):
    for k in [k for k, v in _registro.items() if ahora - v["ts"] > TTL]:
        _registro.pop(k, None)


def reservar(clave_acceso, xml_bytes):
    """Reserva la clave para este documento.

    Devuelve (None, None) si hay que procesar, o (resultado, "replay") si ya se
    proceso identico. Lanza Conflicto si la clave esta tomada por otro documento
    o hay un envio en curso.
    """
    h = huella(xml_bytes)
    ahora = time.time()
    with _lock:
        _purgar(ahora)
        previo = _registro.get(clave_acceso)
        if previo is None:
            _registro[clave_acceso] = {"huella": h, "ts": ahora,
                                       "estado": "en_curso", "resultado": None}
            return None, None
        if previo["huella"] != h:
            raise Conflicto(
                "La clave de acceso ya se uso para un comprobante distinto")
        if previo["estado"] == "en_curso":
            raise Conflicto("Ese comprobante ya se esta enviando")
        return previo["resultado"], "replay"


def completar(clave_acceso, resultado):
    with _lock:
        if clave_acceso in _registro:
            _registro[clave_acceso].update(estado="completo", resultado=resultado)


def liberar(clave_acceso):
    """Se llama si el envio fallo: la clave queda libre para reintentar."""
    with _lock:
        if _registro.get(clave_acceso, {}).get("estado") == "en_curso":
            _registro.pop(clave_acceso, None)
