# SRI Proxy XAdES-BES

Proxy compatible con la pantalla de Facturacion Electronica del sitio San Joaquin.

El proxy anterior firma con XMLDSig basico. El SRI Ecuador exige XAdES-BES 1.3.2
enveloped; por eso responde `39 FIRMA INVALIDA`. Este proxy conserva los mismos
endpoints que usa `admin.html`:

- `GET /health`
- `POST /firmar`
- `POST /recepcion`
- `POST /autorizacion`

## Variables de entorno

- `P12_B64`: certificado `.p12/.pfx` en base64.
- `P12_PASS`: contrasena del certificado.
- `CORS_ORIGIN`: origenes permitidos, separados por coma.

Ejemplo:

```text
CORS_ORIGIN=https://sanjoaquinartesaniacarnica.com,https://san-joaquin-artesania-carnica.web.app
```

## Railway

Desplegar esta carpeta como servicio Python en Railway. El `Procfile` inicia
Gunicorn automaticamente.

Despues de desplegar, configurar en el panel:

```text
https://TU-SERVICIO.up.railway.app
```

como `URL del Proxy SRI` dentro de Configuracion del Sistema.

## Nota de licencia

La libreria `sri-xades-signer` declara licencia AGPL-3.0. Si se usa en un
servicio publico, revisar obligaciones de licencia antes de ponerlo en
produccion.
