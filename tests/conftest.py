"""Arranque del proxy para pruebas.

Nunca se usa el certificado real: `P12_B64` se deja vacio a proposito, de modo
que ningun test puede provocar una firma con la clave de produccion.
"""
import os
import sys
import pathlib

os.environ.setdefault("ALLOWED_ORIGIN", "https://ejemplo.test")
os.environ.pop("P12_B64", None)
os.environ.pop("P12_PASS", None)
os.environ.pop("PAYPHONE_TOKEN", None)

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
import sri_proxy


@pytest.fixture
def app():
    sri_proxy.app.config.update(TESTING=True)
    return sri_proxy.app


@pytest.fixture
def client(app):
    # El rate limit vive en memoria del proceso: sin limpiarlo entre pruebas,
    # una prueba contamina a la siguiente. Que haga falta esto ya es el sintoma.
    sri_proxy._rate_store.clear()
    return app.test_client()
