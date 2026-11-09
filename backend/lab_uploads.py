"""Safe append-only ingestion of lab logs into Wazuh monitored files."""
import ipaddress
import json
import logging
import os
import re
import stat
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing

from flask import g, jsonify, request

import database
from roles_audit import request_username

logger = logging.getLogger(__name__)

SAMPLES = Path(__file__).parent / "lab_samples"
MAX_BYTES = 1024 * 1024
MAX_LINES = 2000
PLATFORMS = {"linux", "syslog", "web"}
WINDOWS_PLATFORM_ERROR = "Windows event logs are unsupported as text uploads; use a Wazuh agent with EventChannel collection"
READ_CONFIRM_WINDOW_SECONDS = 30 * 60
_counts = {}
_count_lock = threading.Lock()
_ISO = re.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?")
_SYSLOG = re.compile(r"^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d\d:\d\d:\d\d")
_APACHE = re.compile(r"\[\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\]")
_IP = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]{0,4}(?![\w:])")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_content(raw):
    if not raw or len(raw) > MAX_BYTES or b"\0" in raw:
        raise ValueError("File must be non-empty, at most 1 MiB, and contain no null bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("File must be UTF-8 text") from None
    if any((ord(c) < 32 and c not in "\n\r\t") or ord(c) == 127 for c in text):
        raise ValueError("Binary content is not allowed")
    lines = text.splitlines()
    if not lines or len(lines) > MAX_LINES or any(not line for line in lines):
        raise ValueError("File must contain 1-2000 non-empty lines")
    for match in _IP.finditer(text):
        try:
            addr = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        allowed_doc = any(addr in ipaddress.ip_network(net) for net in (
            "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
        if addr.is_global and not allowed_doc:
            raise ValueError("Public IP addresses are not allowed")
    now = datetime.now(timezone.utc)
    rewritten = []
    for line in lines:
        if _ISO.match(line):
            stamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
            line = _ISO.sub(stamp, line, count=1)
        elif _SYSLOG.match(line):
            stamp = now.strftime("%b %d %H:%M:%S")
            line = _SYSLOG.sub(stamp, line, count=1)
        elif _APACHE.search(line):
            stamp = now.strftime("[%d/%b/%Y:%H:%M:%S +0000]")
            line = _APACHE.sub(stamp, line, count=1)
        else:
            line = f"{now.isoformat(timespec='seconds')} {line}"
        rewritten.append(line)
    return rewritten


def _target():
    raw = os.environ.get("SOC_AI_INJECT_PATH", "").strip()
    allowed = os.environ.get("SOC_AI_INJECT_ALLOWED_DIR", "").strip()
    if not raw or not allowed:
        raise ValueError("SOC_AI_INJECT_PATH and SOC_AI_INJECT_ALLOWED_DIR must be configured")
    path, root = Path(raw).expanduser(), Path(allowed).expanduser().resolve(strict=True)
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != path.parent.anchor):
        raise ValueError("Symlink paths are not allowed")
    resolved = path.resolve(strict=False)
    if not resolved.is_relative_to(root) or resolved == root or not resolved.parent.is_dir():
        raise ValueError("Target path must stay inside the allowed directory")
    if resolved.exists() and not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError("Target must be a regular file")
    return resolved


def _append(path, rows):
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o640)
    try:
        with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as handle:
            handle.writelines(row + "\n" for row in rows)
    finally:
        os.close(fd)


def _wazuh_read_state(target, uploaded_at):
    """Confirm a recent alert from the monitored file, without depending on marker parsing."""
    alerts_path = Path(os.environ.get("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
    try:
        uploaded = datetime.fromisoformat(uploaded_at.replace("Z", "+00:00"))
        if uploaded.tzinfo is None:
            uploaded = uploaded.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if (now - uploaded).total_seconds() > READ_CONFIRM_WINDOW_SECONDS:
            return False, "Upload is older than the 30-minute confirmation window"
        with alerts_path.open("rb") as alerts_file:
            alerts_file.seek(0, os.SEEK_END)
            size = alerts_file.tell()
            alerts_file.seek(max(0, size - 4 * 1024 * 1024))
            content = alerts_file.read().decode("utf-8", errors="replace")
        lines = content.splitlines()
        if size > 4 * 1024 * 1024 and lines:
            lines = lines[1:]
        target_path = str(Path(target).resolve())
        for line in reversed(lines):
            try:
                alert = json.loads(line)
                location = alert.get("location")
                timestamp = alert.get("timestamp")
                if not isinstance(location, str) or not isinstance(timestamp, str):
                    continue
                if str(Path(location).resolve()) != target_path:
                    continue
                observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if observed.tzinfo is None:
                    observed = observed.replace(tzinfo=timezone.utc)
                if uploaded <= observed <= now:
                    return True, "A recent alert from the monitored upload file was found"
            except (ValueError, TypeError, OSError):
                continue
        return False, "No alert from the monitored upload file was found after the latest upload"
    except PermissionError:
        return False, "Backend cannot read Wazuh alerts.json; grant the backend read permission"
    except FileNotFoundError:
        return False, "Wazuh alerts.json was not found; configure WAZUH_ALERTS_FILE"
    except (OSError, ValueError):
        return False, "Wazuh alerts.json could not be checked"


def register_lab_routes(app):
    @app.before_request
    def allow_multipart_overhead_for_lab_file():
        if request.path == "/api/lab/uploads" and request.method == "POST":
            request.max_content_length = MAX_BYTES + 64 * 1024

    def enabled():
        return os.environ.get("SOC_AI_INJECT_ENABLED", "false").strip().lower() == "true"

    def rate_check(user):
        now = datetime.now(timezone.utc).timestamp()
        with _count_lock:
            points = [t for t in _counts.get(user, []) if now - t < 60]
            if len(points) >= 3:
                return False
            points.append(now)
            _counts[user] = points
            return True

    def save_upload(raw, title, platform, user, upload_id):
        if not enabled():
            return None, (jsonify(ok=False, error="Lab injection is disabled"), 403)
        if not isinstance(title, str) or not title.strip() or len(title.strip()) > 120:
            return None, (jsonify(ok=False, error="A title of 1-120 characters is required"), 400)
        if platform not in PLATFORMS:
            message = WINDOWS_PLATFORM_ERROR if platform == "windows" else "platform must be linux, syslog, or web"
            return None, (jsonify(ok=False, error=message, message=message), 400)
        try:
            rows = _clean_content(raw)
            path = _target()
        except (ValueError, OSError, RuntimeError) as error:
            return None, (jsonify(ok=False, error=str(error)), 400)
        if not rate_check(user):
            return None, (jsonify(ok=False, error="Lab upload rate limit exceeded"), 429)
        try:
            _append(path, [f"# SOCLAB-INJECT upload={upload_id}", *rows])
        except OSError:
            return None, (jsonify(ok=False, error="Target file could not be appended"), 400)
        uploaded_at = _now()
        with closing(database.get_connection()) as connection, connection:
            connection.execute("INSERT INTO lab_uploads VALUES (?, ?, ?, ?, ?, ?)",
                (upload_id, user, title.strip(), platform, len(rows), uploaded_at))
            connection.execute("INSERT INTO audit_log (username, action, object_type, object_id, occurred_at, details_json) VALUES (?, 'lab_upload', 'lab_upload', ?, ?, ?)",
                (user, upload_id, uploaded_at, '{"line_count":%d,"platform":"%s"}' % (len(rows), platform)))
        return {"id": upload_id, "username": user, "title": title.strip(), "platform": platform,
                "line_count": len(rows), "uploaded_at": uploaded_at}, None

    @app.get("/api/lab/status")
    def lab_status():
        try:
            path = _target()
            exists = path.exists()
            writable = path.parent.is_dir() and os.access(path if exists else path.parent, os.W_OK)
        except (ValueError, OSError, RuntimeError):
            exists = writable = False
        with closing(database.get_connection()) as connection:
            count = connection.execute("SELECT COUNT(*) FROM lab_uploads").fetchone()[0]
            latest = connection.execute("SELECT uploaded_at FROM lab_uploads ORDER BY uploaded_at DESC LIMIT 1").fetchone()
        confirmed, confirmation_reason = _wazuh_read_state(path if exists else os.environ.get("SOC_AI_INJECT_PATH", ""), latest["uploaded_at"] if latest else "") if latest else (False, "Upload a log before checking for Wazuh alerts")
        return jsonify(ok=True, injection_enabled=enabled(), target_exists=exists, target_writable=writable,
                       uploads_exist=count > 0, setup_needed=["Add the <localfile> entry shown in docs/LAB_SETUP.md to ossec.conf", "Restart wazuh-manager after adding the entry"],
                       wazuh_read_confirmed=confirmed, wazuh_read_reason=confirmation_reason)

    @app.get("/api/lab/uploads")
    def list_lab_uploads():
        user = request_username()
        is_admin = database.get_soc_user_role(user) == "admin"
        query = "SELECT * FROM lab_uploads" + ("" if is_admin else " WHERE username = ?") + " ORDER BY uploaded_at DESC"
        with closing(database.get_connection()) as connection:
            rows = connection.execute(query, () if is_admin else (user,)).fetchall()
        return jsonify(ok=True, uploads=[dict(row) for row in rows])

    @app.delete("/api/lab/uploads/<upload_id>")
    def delete_lab_upload(upload_id):
        user = request_username()
        with closing(database.get_connection()) as connection, connection:
            row = connection.execute("SELECT * FROM lab_uploads WHERE upload_id = ?", (upload_id,)).fetchone()
            if row is None or (row["username"] != user and database.get_soc_user_role(user) != "admin"):
                return jsonify(ok=False, error="Upload not found"), 404
            connection.execute("DELETE FROM lab_uploads WHERE upload_id = ?", (upload_id,))
        database.record_audit_event(user, "lab_upload_record_deleted", "lab_upload", upload_id,
            _now(), {"alerts_remain_in_wazuh": True})
        return jsonify(ok=True, message="Platform upload record deleted. Alerts already created in Wazuh cannot be removed by this tool.", alerts_remain_in_wazuh=True)

    @app.get("/api/lab/samples")
    def list_lab_samples():
        return jsonify(ok=True, samples=[{"name": path.name, "title": path.stem.replace("_", " ").title()} for path in sorted(SAMPLES.glob("*.log"))])

    @app.post("/api/lab/uploads")
    def create_lab_upload():
        upload_id = getattr(g, "lab_upload_id", uuid.uuid4().hex)
        user = request_username()
        try:
            upload = request.files.get("file")
            if upload is not None:
                filename, raw = upload.filename, upload.read(MAX_BYTES + 1)
                title, platform = request.form.get("title"), request.form.get("platform")
            else:
                payload = request.get_json(silent=True) if request.is_json else None
                if not isinstance(payload, dict):
                    return jsonify(ok=False, error="Choose a .log or .txt file", message="Choose a .log or .txt file"), 400
                filename, content = payload.get("filename"), payload.get("content")
                if not isinstance(content, str):
                    return jsonify(ok=False, error="File content must be text", message="File content must be text"), 400
                raw = content.encode("utf-8")
                title, platform = payload.get("title"), payload.get("platform")
            if not isinstance(filename, str) or not filename.lower().endswith((".log", ".txt")):
                return jsonify(ok=False, error="Choose a .log or .txt file", message="Choose a .log or .txt file"), 400
            result, error = save_upload(raw, title, platform, user, upload_id)
            if error:
                return error
            return jsonify(ok=True, upload=result), 201
        except Exception:
            logger.exception("Lab upload failed status=500 reason=metadata_or_route_error upload_id=%s", upload_id)
            return jsonify(ok=False, error="Lab upload could not be completed", message="Lab upload could not be completed"), 500

    @app.post("/api/lab/samples/<name>")
    def load_lab_sample(name):
        upload_id = getattr(g, "lab_upload_id", uuid.uuid4().hex)
        if name not in {"ssh_bruteforce.log", "sudo_escalation.log", "web_scan.log"}:
            return jsonify(ok=False, error="Sample not found", message="Sample not found"), 404
        try:
            path = SAMPLES / name
            platform = "web" if name == "web_scan.log" else "linux"
            result, error = save_upload(path.read_bytes(), name.removesuffix(".log").replace("_", " ").title(), platform, request_username(), upload_id)
            if error:
                return error
            return jsonify(ok=True, upload=result), 201
        except Exception:
            logger.exception("Lab sample upload failed status=500 reason=sample_or_metadata_error upload_id=%s", upload_id)
            return jsonify(ok=False, error="Sample upload could not be completed", message="Sample upload could not be completed"), 500
