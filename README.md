# パスワード金庫

各サイトのログインID・パスワードを管理するアプリ（完全ローカル／無料）。
**ゼロ知識方式**：暗号化・復号はすべてブラウザの中で行い、サーバーには
「暗号化されたカタマリ」しか保存されません。マスターパスワードはサーバーに送られません。

## 使い方（このPC）
```
cd ~/パスワード管理
PORT=5007 python3 app.py
```
ブラウザで http://localhost:5007/ を開く。
初回は「マスターパスワード（合言葉）」を設定 → 2回目以降はそれで開錠。

⚠️ **マスターパスワードを忘れると中身は誰にも復元できません。** 紙等で安全に保管してください。

## 仕組み（安全設計）
- マスターパスワード → PBKDF2(60万回, SHA-256, ソルト付き)で512bit導出
  - 前半256bit = AES-GCM暗号鍵（**ブラウザ内のみ**・サーバーに渡らない）
  - 後半256bit = 認証ハッシュ（サーバーがログイン確認に使用。さらにハッシュ化して保存）
- 金庫データはAES-GCMで暗号化してから保存。
- サーバーが持つのは：ソルト／認証ハッシュ／暗号文／IV のみ。

## データ
- `data/vault.db`（SQLite）。バックアップはこのファイルをコピーするだけ。
- 環境変数 `VAULT_DB_PATH` で保存先を変更可能。

## iPhoneからも使う（公開手順・無料）
GitHub: https://github.com/xkx0xux/password-vault （非公開）

### ① 永続DBを用意（Neon・無料）
1. https://neon.tech にGitHubでサインアップ
2. プロジェクトを新規作成（設定はそのままでOK）
3. 表示される **接続文字列（Connection string）** をコピー
   例：`postgresql://user:pass@ep-xxx.neon.tech/neondb?sslmode=require`

### ② Renderで公開（無料）
1. https://render.com → New → **Blueprint**
2. リポジトリ `password-vault` を選択（このリポジトリの `render.yaml` を自動認識）
3. 環境変数 **DATABASE_URL** に ①の接続文字列を貼り付け → Apply / Deploy
4. 数分で `https://vault-password-manager.onrender.com` 等のURLが発行される

### ③ iPhoneで使う
- そのURLをSafariで開く → 共有 → **「ホーム画面に追加」** でアプリ化
- 初回はマスターパスワードを設定（公開版は新しい金庫＝ローカル版とは別データ）

### 同期について
PCもiPhoneも **同じRenderのURL** を開けば、データはNeonで共有＝同期されます。
（`localhost:5007` のローカル版はオフライン用の別データです）

### 仕様メモ
- crypto APIは https 必須 → Renderはhttpsなので動作OK。
- 無料枠は約15分アクセスが無いとスリープ → 次回の初回表示が30〜60秒遅いことがある。
- Render内蔵のPostgres無料枠は期限切れで消えるため使わない（外部のNeonを使う）。
