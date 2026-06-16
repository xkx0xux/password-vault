"""
パスワード管理アプリ（ゼロ知識方式・複数ユーザー対応）

このサーバーは「暗号化されたカタマリ」しか扱いません。
- マスターパスワードはサーバーに送られません。
- 暗号化・復号はすべてブラウザ（クライアント）側で行われます。
- サーバーが保存するのは「メール・ソルト・認証ハッシュ・暗号文・IV」だけ。
- ユーザーごとに1つの金庫（vaults テーブルの1行）。互いの中身は暗号化のため見えません。

保存先：
- ローカル（PC）……SQLite（data/vault.db）
- 公開（Render等）…環境変数 VAULT_DB（または DATABASE_URL）に PostgreSQL の接続文字列

環境変数：
- VAULT_DB / DATABASE_URL : DB接続文字列（無ければ SQLite）
- SIGNUP_CODE             : 登録時の合言葉（招待コード）。設定すると登録に必須。空なら誰でも登録可。
"""
import os
import re

from flask import Flask, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 接続文字列があれば PostgreSQL、無ければローカル SQLite。
# ※Renderは予約名 DATABASE_URL に postgres URL を設定できないため VAULT_DB を優先。
DATABASE_URL = (os.environ.get("VAULT_DB") or os.environ.get("DATABASE_URL", "")).strip()
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
USE_PG = DATABASE_URL.startswith("postgresql://")

# 登録用の招待コード（任意）。設定されていれば登録時に一致が必要。
SIGNUP_CODE = os.environ.get("SIGNUP_CODE", "").strip()

if USE_PG:
    import psycopg2
    if "sslmode=" not in DATABASE_URL:
        DATABASE_URL += ("&" if "?" in DATABASE_URL else "?") + "sslmode=require"
    PH = "%s"
else:
    import sqlite3
    DB_PATH = os.environ.get("VAULT_DB_PATH", os.path.join(BASE_DIR, "data", "vault.db"))
    PH = "?"

COLS = ("salt", "auth_hash", "ciphertext", "iv", "updated_at")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__)


def get_conn():
    if USE_PG:
        return psycopg2.connect(DATABASE_URL)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS vaults (
            email       TEXT PRIMARY KEY,
            salt        TEXT NOT NULL,
            auth_hash   TEXT NOT NULL,
            ciphertext  TEXT NOT NULL,
            iv          TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def norm_email(value):
    return (value or "").strip().lower()


def fetch_user(email):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"SELECT {', '.join(COLS)} FROM vaults WHERE email = {PH}", (email,))
    row = cur.fetchone()
    conn.close()
    return dict(zip(COLS, row)) if row else None


def verify_auth(row, data):
    auth = (data or {}).get("authHash", "")
    return bool(auth) and check_password_hash(row["auth_hash"], auth)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    """メールが登録済みか、そのソルトを返す（ログイン/新規登録の振り分け用）。"""
    data = request.get_json(silent=True) or {}
    email = norm_email(data.get("email"))
    if not EMAIL_RE.match(email):
        return jsonify({"error": "invalid_email"}), 400
    row = fetch_user(email)
    if row is None:
        return jsonify({"exists": False, "salt": None})
    return jsonify({"exists": True, "salt": row["salt"]})


@app.route("/api/register", methods=["POST"])
def api_register():
    """新規アカウント作成。"""
    data = request.get_json(silent=True) or {}
    email = norm_email(data.get("email"))
    if not EMAIL_RE.match(email):
        return jsonify({"error": "invalid_email"}), 400
    if SIGNUP_CODE and (data.get("signupCode", "").strip() != SIGNUP_CODE):
        return jsonify({"error": "bad_signup_code"}), 403
    for key in ("salt", "authHash", "ciphertext", "iv"):
        if not data.get(key):
            return jsonify({"error": f"missing_{key}"}), 400
    if fetch_user(email) is not None:
        return jsonify({"error": "already_exists"}), 409

    stamp = now_iso()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO vaults (email, salt, auth_hash, ciphertext, iv, created_at, updated_at) "
        f"VALUES ({PH}, {PH}, {PH}, {PH}, {PH}, {PH}, {PH})",
        (
            email,
            data["salt"],
            generate_password_hash(data["authHash"]),
            data["ciphertext"],
            data["iv"],
            stamp,
            stamp,
        ),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/unlock", methods=["POST"])
def api_unlock():
    """認証ハッシュを検証し、暗号文を返す。"""
    data = request.get_json(silent=True) or {}
    email = norm_email(data.get("email"))
    row = fetch_user(email)
    if row is None:
        return jsonify({"error": "not_found"}), 404
    if not verify_auth(row, data):
        return jsonify({"error": "invalid_password"}), 401
    return jsonify(
        {"ciphertext": row["ciphertext"], "iv": row["iv"], "updated_at": row["updated_at"]}
    )


@app.route("/api/save", methods=["POST"])
def api_save():
    """暗号化済みの金庫を保存（上書き）。認証ハッシュで本人確認。"""
    data = request.get_json(silent=True) or {}
    email = norm_email(data.get("email"))
    row = fetch_user(email)
    if row is None:
        return jsonify({"error": "not_found"}), 404
    if not verify_auth(row, data):
        return jsonify({"error": "invalid_password"}), 401
    for key in ("ciphertext", "iv"):
        if not data.get(key):
            return jsonify({"error": f"missing_{key}"}), 400

    stamp = now_iso()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        f"UPDATE vaults SET ciphertext = {PH}, iv = {PH}, updated_at = {PH} WHERE email = {PH}",
        (data["ciphertext"], data["iv"], stamp, email),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "updated_at": stamp})


# gunicorn でも __main__ を通らずにテーブルを用意できるよう、読み込み時に初期化
init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5007))
    app.run(host="0.0.0.0", port=port, debug=False)
