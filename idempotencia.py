"""Idempotencia fiscal por clave de acceso del SRI.

Un comprobante ya tiene identidad unica: su clave de acceso de 49 digitos. No
hace falta inventar otra, y hacerlo seria peor -- dos identidades para la misma
factura acaban discrepando.

Reglas:
  misma clave + mismo documento  -> se devuelve el resultado anterior
  misma clave + documento distinto -> conflicto, no se envia
  clave en curso                 -> conflicto, no se procesa en paralelo

La reserva es atomica ENTRE WORKERS, y no hace falta infraestructura nueva para
lograrlo. Los workers de gunicorn son procesos del mismo contenedor, asi que
comparten el sistema de archivos, y crear un archivo con O_CREAT|O_EXCL es una
operacion atomica del sistema operativo: exactamente un proceso gana. Eso resuelve
la carrera sin Redis, sin base de datos y sin coste nuevo.

Limitacion que conviene tener escrita: esto vale para varios workers de un mismo
contenedor, no para varias instancias. Si algun dia el servicio escala a mas de
un contenedor, la reserva tiene que mudarse a un almacen compartido de verdad.
"""

import errno
import hashlib
import json
import os
import tempfile
import threading
import time

TTL = 24 * 3600

# Dentro del contenedor. Se limpia al reiniciar, que es correcto: una reserva
# huerfana de un proceso muerto no debe bloquear para siempre.
DIRECTORIO = os.environ.get("IDEMPOTENCIA_DIR") or os.path.join(
    tempfile.gettempdir(), "sri-idempotencia")

_lock = threading.Lock()
_registro = {}


def _ruta(clave_acceso):
    seguro = "".join(c for c in clave_acceso if c.isalnum())[:64]
    return os.path.join(DIRECTORIO, seguro + ".json")


def _leer(ruta):
    try:
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _escribir(ruta, datos):
    # Escritura por reemplazo: nadie lee un archivo a medio escribir.
    tmp = ruta + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(datos, f)
    os.replace(tmp, ruta)


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
    try:
        for nombre in os.listdir(DIRECTORIO):
            ruta = os.path.join(DIRECTORIO, nombre)
            try:
                if ahora - os.path.getmtime(ruta) > TTL:
                    os.unlink(ruta)
            except OSError:
                pass
    except OSError:
        pass


def reservar(clave_acceso, xml_bytes):
    """Reserva la clave para este documento.

    Devuelve (None, None) si hay que procesar, o (resultado, "replay") si ya se
    proceso identico. Lanza Conflicto si la clave esta tomada por otro documento
    o hay un envio en curso.
    """
    h = huella(xml_bytes)
    ahora = time.time()
    os.makedirs(DIRECTORIO, exist_ok=True)
    ruta = _ruta(clave_acceso)

    with _lock:  # ordena los hilos de ESTE worker antes de tocar el disco
        _purgar(ahora)
        try:
            # O_EXCL: si el archivo ya existe, falla. Es la operacion atomica
            # que decide quien gana la carrera, tambien entre workers.
            fd = os.open(ruta, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise
            previo = _leer(ruta) or {}
            if previo.get("huella") != h:
                raise Conflicto(
                    "La clave de acceso ya se uso para un comprobante distinto")
            if previo.get("estado") == "en_curso":
                raise Conflicto("Ese comprobante ya se esta enviando")
            return previo.get("resultado"), "replay"
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"huella": h, "ts": ahora,
                       "estado": "en_curso", "resultado": None}, f)
        return None, None


def completar(clave_acceso, resultado):
    ruta = _ruta(clave_acceso)
    with _lock:
        datos = _leer(ruta)
        if datos:
            datos.update(estado="completo", resultado=resultado)
            _escribir(ruta, datos)


def liberar(clave_acceso):
    """Se llama si el envio fallo: la clave queda libre para reintentar."""
    ruta = _ruta(clave_acceso)
    with _lock:
        if (_leer(ruta) or {}).get("estado") == "en_curso":
            try:
                os.unlink(ruta)
            except OSError:
                pass
