# Markdown XSS Cookie Lab

最小構成の admin bot 型 XSS CTF です。CSRF で admin セッション内の `greeting` を書き換え、Markdown リンク URL のスキーム検証不足から `javascript:` リンクを生成し、bot のクリックで学習用 FLAG Cookie を送信します。

## 起動

```bash
docker compose up --build
```

- app: `http://localhost:3000`
- attacker: `http://localhost:4000`
- bot: Docker 内部専用

## ローカル確認手順

1. `docker compose up --build`
2. `http://localhost:3000/report` を開く
3. `http://localhost:4000/lab` を報告する
4. admin bot の実行完了を待つ
5. `http://localhost:4000/loot` を開く
6. `flag=FLAG{local_markdown_xss_cookie_lab}` が表示されれば成功

## 外部Webhook確認手順

1. HTTP または HTTPS の Webhook URL を用意する
2. Webhook URL を URL エンコードする
3. `http://localhost:3000/report` を開く
4. 次の形式で報告する

```text
http://localhost:4000/lab?webhook=<URLエンコードしたWebhook URL>
```

5. Webhook に次のような値が届けば成功

```text
flag=FLAG{local_markdown_xss_cookie_lab}
```

## 脆弱性の要点

- `/report` は allowlist 済み URL だけを admin bot に渡します。
- admin bot は `admin_session=1` と学習用 `flag=FLAG{local_markdown_xss_cookie_lab}` Cookie を持った状態で報告 URL を開きます。
- `attacker` の `/lab` は CSRF で `http://app:3000/help/search` に `greeting` を POST します。
- 脆弱版では `/help/search` の POST に CSRF トークン検証がありません。
- `greeting` は HTML タグを無効化した Markdown として表示されますが、Markdown リンク URL のスキーム検証が不足しています。
- `[open](javascript:...)` が `.assistant-message a` として生成され、admin bot が通常クリックします。
- XSS が成立すると `document.cookie` から、この CTF 用に意図的に JavaScript から読める `flag` Cookie だけを抽出して Webhook または `/collect` に送ります。
- XSS が成立すると Cookie が読めるだけでなく、`/api/conversations/latest/subscribers` のような同一オリジン API 操作も可能です。

## SAFE_MODE

次のように起動すると修正版として動作します。

```bash
SAFE_MODE=true docker compose up --build
```

SAFE_MODE では以下を行います。

- `/help/search` の POST に CSRF トークン検証を入れる
- Markdown リンク URL の許可スキームを `http:`, `https:`, `mailto:` のみにする
- `javascript:`, `data:`, `vbscript:` を拒否する
- Markdown レンダリング後に HTML サニタイズを入れる
- 可能な補助防御として bot がセットする `flag` Cookie に `HttpOnly` を付ける

`HttpOnly` は XSS そのものを防ぐ対策ではありません。XSS が成立すると Cookie が読めない場合でも同一オリジン API 操作は可能です。このラボの主防御は CSRF 対策と Markdown URL スキーム検証です。

## 注意書き

- この CTF で Webhook に送る値は、学習用に意図的にセットした疑似 FLAG Cookie と疑似ユーザー情報だけです。
- 実サービスの Cookie や実データを窃取する目的ではありません。
- 実在サービス・第三者環境では使用しないでください。
- 本番では認証 Cookie や機密値に `HttpOnly`, `Secure`, `SameSite` を適切に設定してください。
- bot 自身は環境変数、ローカルファイル、OS 情報、認証情報を Webhook に送る処理を持ちません。

## ファイル構成

```text
docker-compose.yml
app/Dockerfile
app/package.json
app/src/server.js
attacker/Dockerfile
attacker/package.json
attacker/src/server.js
bot/Dockerfile
bot/package.json
bot/src/server.js
README.md
```
