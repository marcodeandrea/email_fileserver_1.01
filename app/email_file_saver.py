#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import imaplib, smtplib, ssl, os, sys, time, uuid, logging
from logging.handlers import RotatingFileHandler
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parseaddr, formatdate
from pathlib import Path
from datetime import datetime

# ========= Helpers & Settings =========
def env_clean(name, fallback=None):
    val = os.getenv(name, fallback if fallback is not None else "")
    if val is None:
        val = ""
    return val.strip().strip('"').strip("'").rstrip("\r").rstrip("\n")

class Settings:
    LOG_FILE = env_clean("LOG_FILE", "/data/logs/worker.log")
    LOG_LEVEL = env_clean("LOG_LEVEL", "INFO").upper()
    INSECURE_SSL = env_clean("INSECURE_SSL", "false").lower() == "true"

    IMAP_HOST = env_clean("IMAP_HOST")
    IMAP_USER = env_clean("IMAP_USER")
    IMAP_PASS = env_clean("IMAP_PASS")
    IMAP_FOLDER = env_clean("IMAP_FOLDER", "INBOX")
    SENDER_FILTER = env_clean("SENDER_FILTER", "drivebackup@hospitalposadas.gob.ar")

    SMTP_HOST = env_clean("SMTP_HOST")
    SMTP_PORT = int(env_clean("SMTP_PORT", "587") or "587")
    SMTP_USER = env_clean("SMTP_USER", IMAP_USER)
    SMTP_PASS = env_clean("SMTP_PASS", IMAP_PASS)
    SMTP_USE_TLS = env_clean("SMTP_USE_TLS", "starttls").lower()  # starttls|ssl

    ERROR_ALERT_TO = env_clean("ERROR_ALERT_TO", "system.warning@hospitalposadas.gob.ar")
    ERROR_ALERT_CC = [x.strip() for x in env_clean("ERROR_ALERT_CC", "").split(",") if x.strip()]
    ERROR_ALERT_ON_EMPTY = env_clean("ERROR_ALERT_ON_EMPTY", "true").lower() == "true"
    SEND_ERROR_TO_SENDER = env_clean("SEND_ERROR_TO_SENDER", "true").lower() == "true"

    DATA_ROOT = Path(env_clean("DATA_ROOT", "/data"))
    MOVE_TO_FOLDER = env_clean("MOVE_TO_FOLDER", "").strip()

    ONLY_ACTIVE_LOGS = env_clean("ONLY_ACTIVE_LOGS", "true").lower() == "true"

    POLL_INTERVAL = int(env_clean("POLL_INTERVAL", "60") or "60")
    ONE_SHOT = env_clean("ONE_SHOT", "false").lower() == "true"

S = Settings()

# ========= Logging =========
log_dir = Path(S.LOG_FILE).parent
try:
    log_dir.mkdir(parents=True, exist_ok=True)
except Exception as e:
    print(f"[INFO] No se pudo crear la carpeta logs {log_dir}: {e}", flush=True)

handlers = [logging.StreamHandler()]
try:
    handlers.append(RotatingFileHandler(S.LOG_FILE, maxBytes=50*1024*1024, backupCount=10, encoding="utf-8"))
except Exception as e:
    print(f"[INFO] No se pudo abrir log archivo {S.LOG_FILE}: {e}", flush=True)

logging.basicConfig(level=S.LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s", handlers=handlers)

def log(msg, level="INFO"):
    getattr(logging, level.lower(), logging.info)(msg)

def ssl_context():
    ctx = ssl.create_default_context()
    if S.INSECURE_SSL:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def getenv_required(name: str) -> str:
    val = os.getenv(name)
    if not val:
        log(f"Falta variable de entorno {name}", "ERROR")
        sys.exit(1)
    return val

# ========= IMAP =========
def connect_imap():
    if not S.IMAP_HOST or not S.IMAP_USER or not S.IMAP_PASS:
        log("Faltan IMAP_HOST/IMAP_USER/IMAP_PASS", "ERROR"); sys.exit(1)
    log(f"Conectando IMAP {S.IMAP_HOST} ...", "DEBUG")
    return imaplib.IMAP4_SSL(S.IMAP_HOST, ssl_context=ssl_context())

def search_messages(imap):
    typ, _ = imap.login(S.IMAP_USER, S.IMAP_PASS)
    if typ != "OK":
        raise RuntimeError("No se pudo loguear en IMAP")
    typ, _ = imap.select(S.IMAP_FOLDER)
    if typ != "OK":
        raise RuntimeError(f"No se pudo seleccionar carpeta {S.IMAP_FOLDER}")
    typ, data = imap.search(None, f'(UNSEEN FROM "{S.SENDER_FILTER}")')
    if typ != "OK":
        raise RuntimeError("Búsqueda IMAP falló")
    ids = data[0].split()
    if ids and not S.ONLY_ACTIVE_LOGS:
        log(f"Encontrados {len(ids)} correo(s) del filtro {S.SENDER_FILTER}", "INFO")
    return ids

def fetch_message(imap, msg_id: bytes):
    typ, data = imap.fetch(msg_id, "(RFC822)")
    if typ != "OK":
        raise RuntimeError("No se pudo descargar el mensaje")
    return BytesParser(policy=policy.default).parsebytes(data[0][1])

# ========= Heurística para detectar respuestas (reply) =========
def is_reply_message(msg) -> bool:
    subject = (msg.get("Subject", "") or "").strip()
    if subject.lower().startswith("re:"):
        return True
    if msg.get("In-Reply-To") or msg.get("References"):
        return True
    return False

# ========= Guardado adjuntos =========
def ensure_dir(path: Path): path.mkdir(parents=True, exist_ok=True)

def save_attachments(msg, base_dir: Path, task_id: str):
    saved = []
    target_dir = base_dir / datetime.now().strftime("%Y/%m/%d")
    ensure_dir(target_dir)
    for part in msg.iter_attachments():
        if (part.get_content_disposition() or "").lower() != "attachment":
            log(f"[Task-id {task_id}] Ignorado no-adjunto: {part.get_filename() or part.get_content_type()}", "DEBUG")
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if not filename or not payload:
            log(f"[Task-id {task_id}] Parte sin filename/payload omitida", "DEBUG")
            continue
        out_path = target_dir / filename
        if out_path.exists():
            out_path = target_dir / f"{out_path.stem}_{int(time.time())}{out_path.suffix}"
        out_path.write_bytes(payload)
        saved.append(out_path)
        log(f"[Task-id {task_id}] Adjunto guardado: {out_path}", "INFO")
    return saved

# ========= SMTP helpers =========
def smtp_send(msg: EmailMessage):
    if not S.SMTP_HOST:
        log("SMTP_HOST no configurado", "ERROR"); return
    ctx = ssl_context()
    if S.SMTP_USE_TLS == "ssl":
        with smtplib.SMTP_SSL(S.SMTP_HOST, S.SMTP_PORT, context=ctx) as s:
            if S.SMTP_USER and S.SMTP_PASS:
                s.login(S.SMTP_USER, S.SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP(S.SMTP_HOST, S.SMTP_PORT) as s:
            s.ehlo(); s.starttls(context=ctx); s.ehlo()
            if S.SMTP_USER and S.SMTP_PASS:
                s.login(S.SMTP_USER, S.SMTP_PASS)
            s.send_message(msg)

def send_confirmation(to_addr: str, subject: str, saved_paths, task_id: str):
    if not to_addr:
        log(f"[Task-id {task_id}] No hay remitente para confirmar.", "INFO")
        return
    m = EmailMessage()
    m["From"] = S.SMTP_USER
    m["To"] = to_addr
    m["Date"] = formatdate(localtime=True)
    m["Subject"] = f"[Confirmación] Archivo recibido y guardado - Re: {subject or ''}"
    body = ("Hola,\n\n"
            "Tu(s) archivo(s) adjunto(s) fueron recibidos y guardados correctamente en el file server.\n\n"
            "Saludos.\n\n Esta es una respuesta automatica. \n\n Email → File Server")
    m.set_content(body)
    log(f"[Task-id {task_id}] Enviando confirmación a {to_addr}", "INFO")
    smtp_send(m)

def send_error_alert(original_from: str, subject: str, reason: str, saved_paths, task_id: str):
    if not S.ERROR_ALERT_TO:
        log("ERROR_ALERT_TO no configurado; se omite alerta.", "INFO")
        return
    m = EmailMessage()
    m["From"] = S.SMTP_USER
    m["To"] = S.ERROR_ALERT_TO
    if S.ERROR_ALERT_CC:
        m["Cc"] = ", ".join(S.ERROR_ALERT_CC)
    m["Date"] = formatdate(localtime=True)
    m["Subject"] = f"[ALERTA] Fallo al guardar adjunto(s) - Re: {subject or ''}"
    listado = "\n".join(f"- {p}" for p in (saved_paths or [])) or "(sin archivos guardados)"
    body = (f"Se detectó un problema al procesar un correo\n\n"
            f"Número de tarea: {task_id}\n"
            f"Remitente original: {original_from or '(desconocido)'}\n"
            f"Asunto: {subject or '(sin asunto)'}\n"
            f"Motivo: {reason}\n\n"
            f"Archivos guardados:\n{listado}\n\n"
            "Sistema: Automatización Email → File Server")
    m.set_content(body)
    log(f"[Task-id {task_id}] Enviando ALERTA a {S.ERROR_ALERT_TO}", "INFO")
    smtp_send(m)

def send_failure_notice(to_addr: str, subject: str, reason: str, task_id: str):
    """Aviso al remitente cuando NO se pudieron guardar adjuntos."""
    if not to_addr:
        log(f"[Task-id {task_id}] No hay destinatario para enviar aviso de error al remitente.", "INFO")
        return
    m = EmailMessage()
    m["From"] = S.SMTP_USER
    m["To"] = to_addr
    m["Date"] = formatdate(localtime=True)
    m["Subject"] = f"[Aviso] No se pudieron procesar tus adjuntos - Re: {subject or ''}"
    body = ("Hola,\n\n"
            "Recibimos tu correo, pero no pudimos procesar los archivos adjuntos.\n"
            f"Motivo: {reason}\n"
            "Por favor, verificá el envío (formato/adjuntos/tamaño) y reintentalo.\n\n"
            "Saludos.\n\n Esta es una respuesta automatica. \n\n Email → File Server")
    m.set_content(body)
    log(f"[Task-id {task_id}] Enviando aviso de error al remitente: {to_addr}", "INFO")
    smtp_send(m)

# ========= Main processing =========
def process_once():
    task_id = uuid.uuid4().hex[:8]
    imap = connect_imap()
    try:
        ids = search_messages(imap)
        if ids:
            log(f"[Task-id {task_id}] Iniciando ciclo: {len(ids)} mensaje(s) pendientes del filtro {S.SENDER_FILTER}", "INFO")
        for msg_id in ids:
            try:
                msg = fetch_message(imap, msg_id)
                from_name, from_addr = parseaddr(msg.get("From", ""))
                subject = msg.get("Subject", "")

                skip_replies = os.getenv("SKIP_REPLIES", "true").lower() == "true"
                replies_folder = os.getenv("REPLIES_MOVE_TO", "").strip()

                if skip_replies and is_reply_message(msg):
                    log(f"Omitido por ser respuesta (reply). From={from_addr} Subject={subject}", "INFO")
                    # Marcar leído para que no reprocese
                    imap.store(msg_id, "+FLAGS", "\\Seen")
                    # (Opcional) mover a carpeta de replies
                    if replies_folder:
                        try:
                            typ, _ = imap.copy(msg_id, replies_folder)
                            if typ == "OK":
                                imap.store(msg_id, "+FLAGS", "\\Deleted")
                                imap.expunge()
                        except Exception as e:
                            log(f"No se pudo mover reply a {replies_folder}: {e}", "INFO")
                    continue
                log(f"[Task-id {task_id}] Procesando mensaje {msg_id.decode()} de {from_addr} - Asunto: {subject}", "INFO")

                # Guardado con captura de error
                try:
                    saved = save_attachments(msg, S.DATA_ROOT, task_id)
                except Exception as e_save:
                    reason = f"Excepción al guardar adjuntos: {e_save}"
                    send_error_alert(from_addr, subject, reason, [], task_id)
                    if S.SEND_ERROR_TO_SENDER:
                        try:
                            send_failure_notice(from_addr, subject, reason, task_id)
                        except Exception as e2:
                            log(f"[Task-id {task_id}] Falló aviso al remitente: {e2}", "ERROR")
                    imap.store(msg_id, "+FLAGS", "\\Seen")
                    continue

                # Caso sin adjuntos guardados
                if S.ERROR_ALERT_ON_EMPTY and not saved:
                    reason = "No se encontró ningún archivo adjunto válido."
                    send_error_alert(from_addr, subject, reason, [], task_id)
                    if S.SEND_ERROR_TO_SENDER:
                        try:
                            send_failure_notice(from_addr, subject, reason, task_id)
                        except Exception as e2:
                            log(f"[Task-id {task_id}] Falló aviso al remitente: {e2}", "ERROR")
                else:
                    if from_addr:
                        send_confirmation(from_addr, subject, saved, task_id)
                    else:
                        log(f"[Task-id {task_id}] Remitente desconocido, no se puede envíar confirmación.", "INFO")

                # Marcar leído y mover si aplica
                imap.store(msg_id, "+FLAGS", "\\Seen")
                if S.MOVE_TO_FOLDER:
                    try:
                        typ, _ = imap.copy(msg_id, S.MOVE_TO_FOLDER)
                        if typ == "OK":
                            imap.store(msg_id, "+FLAGS", "\\Deleted")
                            imap.expunge()
                    except Exception as e:
                        log(f"[Task-id {task_id}] No se pudo mover a {S.MOVE_TO_FOLDER}: {e}", "INFO")

            except Exception as e:
                try:
                    send_error_alert(from_addr if 'from_addr' in locals() else "",
                                     subject if 'subject' in locals() else "",
                                     f"Excepción general: {e}", [], task_id)
                except Exception as e2:
                    log(f"[Task-id {task_id}] Fallo al enviar alerta: {e2}", "ERROR")
                log(f"[Task-id {task_id}] Error procesando mensaje {msg_id.decode()}: {e}", "ERROR")
    finally:
        try:
            imap.close()
        except:
            pass
        imap.logout()

if __name__ == "__main__":
    if S.ONE_SHOT:
        try:
            process_once()
        except Exception as e:
            log(f"Fallo general: {e}", "ERROR"); sys.exit(1)
        sys.exit(0)
    while True:
        try:
            process_once()
        except Exception as e:
            log(f"Fallo general en ciclo: {e}", "ERROR")
        time.sleep(S.POLL_INTERVAL)
