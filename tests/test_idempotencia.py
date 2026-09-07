"""Contrato de idempotencia fiscal."""
import threading
import pytest
import idempotencia as idem

CLAVE = "1" * 49
XML_A = b"<factura>A</factura>"
XML_B = b"<factura>B</factura>"


@pytest.fixture(autouse=True)
def limpio():
    idem._registro.clear()
    yield
    idem._registro.clear()


def test_primera_vez_se_procesa():
    assert idem.reservar(CLAVE, XML_A) == (None, None)


def test_misma_clave_mismo_documento_devuelve_el_resultado_anterior():
    idem.reservar(CLAVE, XML_A)
    idem.completar(CLAVE, {"estado": "AUTORIZADO", "numero": "123"})
    resultado, modo = idem.reservar(CLAVE, XML_A)
    assert modo == "replay"
    assert resultado["numero"] == "123"


def test_misma_clave_documento_distinto_es_conflicto():
    """Lo grave no es reenviar: es enviar OTRO comprobante con la misma clave."""
    idem.reservar(CLAVE, XML_A)
    idem.completar(CLAVE, {"estado": "AUTORIZADO"})
    with pytest.raises(idem.Conflicto):
        idem.reservar(CLAVE, XML_B)


def test_envio_en_curso_bloquea_el_segundo():
    idem.reservar(CLAVE, XML_A)
    with pytest.raises(idem.Conflicto):
        idem.reservar(CLAVE, XML_A)


def test_si_falla_se_libera_para_reintentar():
    idem.reservar(CLAVE, XML_A)
    idem.liberar(CLAVE)
    assert idem.reservar(CLAVE, XML_A) == (None, None)


def test_concurrencia_solo_uno_pasa():
    """Veinte hilos con la misma clave: uno procesa, diecinueve chocan."""
    pasaron, conflictos = [], []
    def intentar():
        try:
            r = idem.reservar(CLAVE, XML_A)
            pasaron.append(r)
        except idem.Conflicto:
            conflictos.append(1)
    hilos = [threading.Thread(target=intentar) for _ in range(20)]
    for h in hilos: h.start()
    for h in hilos: h.join()
    assert len(pasaron) == 1
    assert len(conflictos) == 19


def test_el_xml_no_se_normaliza():
    """Canonicalizar significaria alterar lo que se firmo. Dos formas del mismo
    comprobante se tratan como distintas: el lado seguro del error."""
    assert idem.huella(b"<a> </a>") != idem.huella(b"<a></a>")
    assert idem.huella("<a/>") == idem.huella(b"<a/>")
