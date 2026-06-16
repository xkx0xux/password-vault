"""
パスワード管理アプリ（ゼロ知識方式）

このサーバーは「暗号化されたカタマリ」しか扱いません。
- マスターパスワードはサーバーに送られません。
- 暗号化・復号はすべてブラウザ（クライアント）側で行われます。
- サーバーが保存するのは「暗号文・IV・ソルト・認証ハッシュ」だけ。
  万一DBが漏れても、マスターパスワードが分からなければ中身は読めません。

保存先：
- ローカル（PC）……SQLite（data/vault.db）
- 公開（Render等）…環境変数 DATABASE_URL があれば PostgreSQL(Neon等) を使用
"""
import os

from flask import Flask, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 接続文字列があれば PostgreSQL、無ければローカル SQLite。
# ※Renderは予約名 DATABASE_URL に postgres URL を設定できないため VAULT_DB を優先。
DATABASE_URL = (os.environ.get("VAULT_DB") or os.environ.get("DATABASE_URL", "")).strip()
if DATABASE_URL.startswith("postgres://"):  # 古い形式を正規化
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
USE_PG = DATABASE_URL.startswith("postgresql://")

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
        CREATE TABLE IF NOT EXISTS vault (
            id          INTEGER PRIMARY KEY,
            salt        TEXT NOT NULL,
            auth_hash   TEXT NOT NULL,
            ciphertext  TEXT NOT NULL,
            iv          TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def fetch_vault():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"SELECT {', '.join(COLS)} FROM vault WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    return dict(zip(COLS, row)) if row else None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/meta")
def api_meta():
    """初期化済みか、ソルトを返す（ソルトは秘密ではない）。"""
    row = fetch_vault()
    if row is None:
        return jsonify({"initialized": False, "salt": None})
    return jsonify({"initialized": True, "salt": row["salt"]})


@app.route("/api/setup", methods=["POST"])
def api_setup():
    """初回セットアップ。まだ金庫が無いときだけ受け付ける。"""
    if fetch_vault() is not None:
        return jsonify({"error": "already_initialized"}), 409

    data = request.get_json(silent=True) or {}
    for key in ("salt", "authHash", "ciphertext", "iv"):
        if not data.get(key):
            return jsonify({"error": f"missing_{key}"}), 400

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO vault (id, salt, auth_hash, ciphertext, iv, updated_at) "
        f"VALUES (1, {PH}, {PH}, {PH}, {PH}, {PH})",
        (
            data["salt"],
            generate_password_hash(data["authHash"]),
            data["ciphertext"],
            data["iv"],
            now_iso(),
        ),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


def verify_auth(row, data):
    auth = (data or {}).get("authHash", "")
    return bool(auth) and check_password_hash(row["auth_hash"], auth)


@app.route("/api/unlock", methods=["POST"])
def api_unlock():
    """マスターパスワード由来の認証ハッシュを検証し、暗号文を返す。"""
    row = fetch_vault()
    if row is None:
        return jsonify({"error": "not_initialized"}), 404

    data = request.get_json(silent=True) or {}
    if not verify_auth(row, data):
        return jsonify({"error": "invalid_password"}), 401

    return jsonify(
        {
            "ciphertext": row["ciphertext"],
            "iv": row["iv"],
            "updated_at": row["updated_at"],
        }
    )


@app.route("/api/save", methods=["POST"])
def api_save():
    """暗号化済みの金庫を保存（上書き）。認証ハッシュで本人確認。"""
    row = fetch_vault()
    if row is None:
        return jsonify({"error": "not_initialized"}), 404

    data = request.get_json(silent=True) or {}
    if not verify_auth(row, data):
        return jsonify({"error": "invalid_password"}), 401
    for key in ("ciphertext", "iv"):
        if not data.get(key):
            return jsonify({"error": f"missing_{key}"}), 400

    conn = get_conn()
    cur = conn.cursor()
    stamp = now_iso()
    cur.execute(
        f"UPDATE vault SET ciphertext = {PH}, iv = {PH}, updated_at = {PH} WHERE id = 1",
        (data["ciphertext"], data["iv"], stamp),
    )
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "updated_at": stamp})


# gunicorn でも __main__ を通らずにテーブルを用意できるよう、読み込み時に初期化
init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5007))
    app.run(host="0.0.0.0", port=port, debug=False)
