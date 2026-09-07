"""Asigna o retira permisos fiscales a un usuario de Firebase. NO EJECUTADO.

Los permisos viajan como custom claim dentro del ID token. Ponerlos exige el
Admin SDK, que es una operacion administrativa puntual y fuera de linea -- no
algo que el servicio haga en runtime. Por eso esto es una herramienta y no un
endpoint.

    GOOGLE_APPLICATION_CREDENTIALS=/ruta/sa.json \
    python herramientas/asignar_permisos.py --email alguien@ejemplo --conceder invoice:sign

Reglas que hace cumplir:
  - un solo usuario por ejecucion; no hay comodines ni lotes
  - solo permisos de la lista conocida; un nombre mal escrito aborta
  - muestra el antes y el despues, y pide confirmacion escrita
  - nunca imprime la credencial ni el token
"""
import argparse
import json
import os
import sys

PERMISOS = {
    "invoice:sign": "firmar comprobantes con el certificado de la empresa",
    "invoice:send": "enviar la factura al cliente",
    "sri:issue":    "enviar comprobantes al SRI",
    "sri:read":     "consultar autorizaciones en el SRI",
    "email:send":   "enviar correo operativo",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--conceder", nargs="*", default=[])
    ap.add_argument("--retirar", nargs="*", default=[])
    ap.add_argument("--aplicar", action="store_true",
                    help="sin esto, solo muestra lo que haria")
    a = ap.parse_args()

    desconocidos = [p for p in a.conceder + a.retirar if p not in PERMISOS]
    if desconocidos:
        sys.exit(f"Permiso desconocido: {desconocidos}. Validos: {sorted(PERMISOS)}")
    if not a.conceder and not a.retirar:
        sys.exit("Nada que hacer.")
    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        sys.exit("Falta GOOGLE_APPLICATION_CREDENTIALS. No se asume ninguna por defecto.")

    import firebase_admin
    from firebase_admin import auth, credentials
    firebase_admin.initialize_app(credentials.ApplicationDefault())

    usuario = auth.get_user_by_email(a.email)
    actuales = set((usuario.custom_claims or {}).get("permisos", []))
    nuevos = sorted((actuales | set(a.conceder)) - set(a.retirar))

    print(f"uid    : {usuario.uid}")
    print(f"antes  : {sorted(actuales) or '(ninguno)'}")
    print(f"despues: {nuevos or '(ninguno)'}")
    for p in nuevos:
        print(f"         {p} — {PERMISOS[p]}")

    if not a.aplicar:
        print("\nSimulacion. Anade --aplicar para escribir.")
        return
    if input('\nEscribe "confirmo" para aplicar: ').strip() != "confirmo":
        sys.exit("Cancelado.")

    claims = dict(usuario.custom_claims or {})
    claims["permisos"] = nuevos
    auth.set_custom_user_claims(usuario.uid, claims)
    print("Aplicado. El usuario debe volver a entrar, o el navegador pedir "
          "getIdToken(true), para que el token nuevo lleve los permisos.")


if __name__ == "__main__":
    main()
