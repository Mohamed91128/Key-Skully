from flask import Flask, request, render_template, jsonify, session
from datetime import datetime, timedelta
import uuid
import hashlib
import os
from cryptography.fernet import Fernet
from werkzeug.middleware.proxy_fix import ProxyFix
import base64

import config
import db
import fingerprint

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.Config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=config.Config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SECURE=config.Config.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE=config.Config.SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=config.Config.PERMANENT_SESSION_LIFETIME,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

def get_cipher():
    key = config.Config.ENCRYPTION_KEY
    if not key or len(key) < 32:
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
    try:
        return Fernet(key.encode())
    except Exception:
        return Fernet(base64.urlsafe_b64encode(os.urandom(32)))

cipher = get_cipher()

def _is_fernet_token(value: str) -> bool:
    if not value:
        return False
    try:
        cipher.decrypt(value.encode()).decode()
        return True
    except Exception:
        return False

def _migrate_legacy_uuid_row_if_needed(fp: str, ip: str, row: tuple) -> str:
    # row format from db.fetch_row_by_fingerprint or db.fetch_key:
    # (key, fingerprint, ip, created_at, expires_at, next_gen_at)
    if not row or len(row) < 6:
        return None

    stored_key = row[0]
    if _is_fernet_token(stored_key):
        return stored_key

    token = cipher.encrypt(stored_key.encode()).decode()
    db.insert_key({
        "key": token,
        "fingerprint": fp,
        "ip": ip,
        "created_at": row[3],
        "expires_at": row[4],
        "next_gen_at": row[5],
    })
    return token

@app.route("/")
def index():
    if session.get("user_key") or session.get("fingerprint"):
        session.permanent = True
    return render_template(
        "keygen.html",
        valid_hours=config.Config.KEY_VALID_HOURS,
        cooldown_hours=config.Config.NEW_KEY_WAIT_HOURS,
        generated_now=False,
    )

@app.route("/genkey", methods=["GET", "POST"])
def genkey():
    now = datetime.utcnow()
    now_iso = now.isoformat()
    fp_request, ip = fingerprint.generate_fingerprint()
    fp = session.get("fingerprint")
    if not fp:
        fp = fp_request
        session["fingerprint"] = fp
        session.permanent = True

    # 1️⃣ SESSION CHECK FIRST (CRITICAL)
    user_key = session.get("user_key")
    if user_key:
        row = db.fetch_key(user_key)
        if row and len(row) >= 5 and row[4] > now_iso:  # expires_at
            encrypted = user_key
            # If this is a legacy UUID saved in-session, migrate it to a stable token
            if not _is_fernet_token(encrypted):
                legacy_fp = row[1] if len(row) >= 2 else fp
                legacy_ip = row[2] if len(row) >= 3 else ip
                migrated = _migrate_legacy_uuid_row_if_needed(legacy_fp, legacy_ip, row)
                if migrated:
                    encrypted = migrated
                    session["user_key"] = encrypted
                    session.permanent = True
            return render_template(
                "keygen.html",
                key=encrypted,
                expires_at=row[4],
                valid_hours=config.Config.KEY_VALID_HOURS,
                cooldown_hours=config.Config.NEW_KEY_WAIT_HOURS,
                success=True,
                generated_now=False,
            )

    # 2️⃣ FINGERPRINT CHECK (prevent multiple devices)
    row = db.fetch_valid_key_by_fingerprint(fp, now_iso)
    if row:
        key, expires = row
        # If DB has a legacy UUID in the key column, migrate it to a stable token
        if not _is_fernet_token(key):
            full_row = db.fetch_row_by_fingerprint(fp)
            migrated = _migrate_legacy_uuid_row_if_needed(fp, ip, full_row)
            if migrated:
                key = migrated

        session["user_key"] = key
        session.permanent = True
        encrypted = key
        return render_template(
            "keygen.html",
            key=encrypted,
            expires_at=expires,
            valid_hours=config.Config.KEY_VALID_HOURS,
            cooldown_hours=config.Config.NEW_KEY_WAIT_HOURS,
            success=True,
            generated_now=False,
        )

    # 3️⃣ COOLDOWN CHECK (prevent rapid generation)
    cooldown = db.fetch_cooldown(fp, now_iso)
    if cooldown:
        next_gen_time = datetime.fromisoformat(cooldown[0])
        remaining_minutes = int((next_gen_time - now).total_seconds() // 60)
        return render_template(
            "keygen.html",
            error=f"Please wait {remaining_minutes} minutes before generating a new key",
            cooldown=f"{remaining_minutes} minutes",
            valid_hours=config.Config.KEY_VALID_HOURS,
            cooldown_hours=config.Config.NEW_KEY_WAIT_HOURS,
            generated_now=False,
        ), 429

    # 4️⃣ GENERATE NEW KEY
    new_key = str(uuid.uuid4())
    encrypted_token = cipher.encrypt(new_key.encode()).decode()
    expires_at = now + timedelta(hours=config.Config.KEY_VALID_HOURS)
    next_gen = now + timedelta(hours=config.Config.NEW_KEY_WAIT_HOURS)

    db.insert_key({
        "key": encrypted_token,
        "fingerprint": fp,
        "ip": ip,
        "created_at": now_iso,
        "expires_at": expires_at.isoformat(),
        "next_gen_at": next_gen.isoformat(),
    })

    session["user_key"] = encrypted_token
    session.permanent = True
    encrypted = encrypted_token

    return render_template(
        "keygen.html",
        key=encrypted,
        expires_at=expires_at.isoformat(),
        valid_hours=config.Config.KEY_VALID_HOURS,
        cooldown_hours=config.Config.NEW_KEY_WAIT_HOURS,
        success=True,
        generated_now=True,
    )

@app.route("/verify")
def verify():
    encrypted_key = (request.args.get("key") or "").strip()
    if not encrypted_key:
        return jsonify({"valid": False}), 400

    try:
        cipher.decrypt(encrypted_key.encode()).decode()
    except Exception:
        return jsonify({"valid": False}), 400

    now_iso = datetime.utcnow().isoformat()
    row = db.fetch_key(encrypted_key)
    if not row or len(row) < 5:
        return jsonify({"valid": False}), 403

    expires_at = row[4]
    if not expires_at or expires_at <= now_iso:
        return jsonify({"valid": False}), 403

    return jsonify({"valid": True, "expires_at": expires_at})

@app.route("/validate", methods=["POST"])
def validate():
    try:
        data = request.get_json()
        if not data or "key" not in data:
            return jsonify({"valid": False}), 400

        encrypted_key = (data["key"] or "").strip()
        if not encrypted_key:
            return jsonify({"valid": False}), 400
        try:
            cipher.decrypt(encrypted_key.encode()).decode()
        except Exception:
            return jsonify({"valid": False}), 400

        fp_request, _ = fingerprint.generate_fingerprint()
        now_iso = datetime.utcnow().isoformat()

        fp_candidates = [fp_request]
        fp_session = session.get("fingerprint")
        if fp_session and fp_session not in fp_candidates:
            fp_candidates.append(fp_session)

        row = None
        for fp in fp_candidates:
            r = db.fetch_valid_key_by_fingerprint(fp, now_iso)
            if r and r[0] == encrypted_key:
                row = r
                break

        if not row:
            return jsonify({"valid": False}), 403

        return jsonify({
            "valid": True,
            "expires_at": row[1]
        })

    except Exception as e:
        return jsonify({"valid": False}), 500

@app.route("/status")
def status():
    try:
        user_key = session.get("user_key")
        if user_key:
            row = db.fetch_key(user_key)
            if row and len(row) >= 5:
                now_iso = datetime.utcnow().isoformat()
                if row[4] > now_iso:
                    return jsonify({
                        "has_key": True,
                        "expires_at": row[4],
                        "valid": True
                    })
                else:
                    return jsonify({
                        "has_key": True,
                        "expired": True,
                        "valid": False
                    })
        
        return jsonify({"has_key": False, "valid": False})
    except Exception:
        return jsonify({"has_key": False, "valid": False})

if __name__ == "__main__":
    db.init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
