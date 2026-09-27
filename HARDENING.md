# Proxy SRI — endurecimiento

Estado: **corrección implementada localmente, sin desplegar.**

## El problema

`POST /firmar` no pedía credencial. Con `P12_B64` cargado en el servicio —como
está en producción, confirmado por `/health`— cualquiera que alcanzara la URL
podía enviar un XML arbitrario y recibirlo firmado con el certificado fiscal de
la empresa. El servicio es públicamente alcanzable en Railway.

CORS no lo impedía: instruye a un navegador, y un cliente que no lo sea lo
ignora. El rate limit tampoco: es un `dict` en memoria, por worker.

## Lo implementado

`@requiere_credencial` sobre `/firmar`, `/recepcion`, `/autorizacion`,
`/send-invoice`, `/cert-info` y `/payphone/debug`.

- secreto compartido en cabecera `X-Proxy-Key`
- **no se acepta por query string**: las URLs acaban en logs de acceso, historial
  y `Referer`
- comparación en tiempo constante (`hmac.compare_digest`)
- el valor recibido **nunca se registra**, ni truncado
- `/health` deja de publicar la lista de orígenes y el correo del administrador

## Por qué hay un interruptor

`PROXY_AUTH_ENFORCE` está separado de la presencia de la clave, y por defecto
apagado.

**Quien llama a `/firmar` hoy es `public/admin.html`, desde el navegador**
(líneas 10793 y 14049). Activar la exigencia sin migrar antes ese consumidor deja
al negocio sin facturar.

Y meter la clave en el JavaScript público **no es una solución**: sería publicar
la credencial que protege el certificado fiscal.

Secuencia correcta:

1. desplegar con `PROXY_AUTH_ENFORCE=false` → no cambia nada, pero registra en
   logs cada llamada sin credencial
2. observar quién llama de verdad
3. mover la llamada a una capa servidor (la FastAPI ya decidida), que sí puede
   guardar el secreto
4. `PROXY_AUTH_ENFORCE=true`

El paso 3 es el trabajo real. Los pasos 1 y 4 son una variable de entorno.

## Variables nuevas

| Variable | Efecto |
|---|---|
| `PROXY_API_KEY` | el secreto. Vacío = control inactivo |
| `PROXY_AUTH_ENFORCE` | `true` exige; cualquier otra cosa sólo registra |
| `EXPOSE_DEBUG` | reservado para retirar debug por entorno |

Ninguna en el repositorio. Se configuran en Railway.

## Rollback

Poner `PROXY_AUTH_ENFORCE=false` y reiniciar. Vuelve al comportamiento anterior
sin desplegar código. Si hiciera falta más, revertir el commit.

## Pruebas

```bash
python3 -m venv .venv-test && ./.venv-test/bin/pip install flask==3.0.3 flask-cors==4.0.1 requests pytest
./.venv-test/bin/python -m pytest tests/ -q
```

29 pruebas. Ninguna llama al SRI, a PayPhone ni a producción, y ninguna usa el
certificado real: `conftest.py` borra `P12_B64` del entorno a propósito.

## Lo que NO se ha tocado

- `/payphone/webhook` sigue sin verificar autenticidad. **No inventé una firma
  para PayPhone**: hay que averiguar primero qué mecanismo soporta realmente
- idempotencia de emisión
- `_token_store` en memoria
- los dos `app.py` divergentes

## Pagos: solo el backend (27/09/2026)

`/payphone/link`, `/payphone/confirm`, `/payphone/status`, `/payphone/confirmed/<tx>` y
`/payphone/button-confirm` eran públicos: cualquiera podía crear enlaces de cobro a nombre del
comercio o consultar transacciones con datos del pagador. Ahora exigen la cabecera
`X-SJ-Servicio-Pagos`, que solo envía el backend de la web (Firebase Functions, `commerceStaffApi`).

| Operación | Endpoints |
|---|---|
| `crear_enlace` | `/payphone/link` |
| `consultar` | `/payphone/confirm`, `/payphone/status`, `/payphone/confirmed/<tx>` |
| `confirmar` | `/payphone/button-confirm` |

- Sin cabecera: 401. Cabecera incorrecta: 403. Sin `PROXY_PAGOS_KEY` (o con menos de 32
  caracteres): 503. Falla cerrado.
- No se acepta en su lugar un token de Firebase ni `PROXY_API_KEY`, y la credencial de pagos no
  abre `/firmar`, `/cert-info` ni `/payphone/debug`.
- El token de PayPhone sigue siendo `PAYPHONE_TOKEN` de Railway. Ya no se admite un token en el
  cuerpo de la petición.
- `/payphone/webhook` sigue público (lo llama PayPhone) y sigue confirmando con `PAYPHONE_TOKEN`.
  Es la única ruta de pagos que puede reenviarse al proxy legado.
- Los registros ya no incluyen cuerpos ni respuestas de PayPhone (datos del pagador), solo el
  código HTTP y el identificador de la transacción.

| Variable nueva | Efecto |
|---|---|
| `PROXY_PAGOS_KEY` | credencial de servicio del backend (el mismo valor que el secreto `PROXY_PAGOS_KEY` de Firebase). Vacía = pagos cerrados (503) |

Orden: primero la variable en Railway y el secreto en Firebase, después Functions y la web, y
por último este código. Mientras tanto, el código anterior ignora la cabecera y sigue funcionando.

Pruebas: `tests/test_pagos_servicio.py`.
