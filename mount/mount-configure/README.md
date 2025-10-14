# Email → File Server Worker

Descarga adjuntos de correos del remitente `drivebackup@hospitalposadas.gob.ar`, guarda los archivos en `/data/YYYY/MM/DD/`, y envía una confirmación al remitente original.

## Uso rápido

```bash
cp .env.example .env
# Edita .env con tus hosts/credenciales
docker compose up -d --build
```

Estructura de guardado:
```
/data/2025/10/02/archivo.pdf
```

Variables clave en `.env`:
- `IMAP_HOST`, `IMAP_USER`, `IMAP_PASS`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USE_TLS`
- `SENDER_FILTER` (remitente a procesar)
- `DATA_ROOT` (punto de montaje del file server)
- `POLL_INTERVAL` (segundos entre escaneos)
- `INSECURE_SSL` (solo pruebas; deshabilita validación TLS)

### Modo una sola pasada
```bash
ONE_SHOT=true docker compose run --rm email_file_worker
```

### Logs
Se imprimen por STDOUT (docker logs). Puedes redirigirlos a archivo con `docker compose` o usar `docker logs -f email_file_worker`.
