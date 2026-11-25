# templ-lint (日本語)

[a-h/templ](https://github.com/a-h/templ) の `.templ` ファイルを templ 公式の
`parser/v2` で直接解析し、**htmx / Alpine.js** 併用時に XSS へつながる記述を
検出するセキュリティリンタ。

## 背景

templ はテキスト補間・属性値を HTML エスケープするが、それでは防げない領域がある:

```
<div x-init={ userInput }>
```

Alpine.js は**属性値の文字列をそのまま JavaScript として評価する**。値は
エスケープ済みでも、Alpine が DOM から文字列を読み戻して実行するため XSS になる。
`hx-on:*`、`hx-vals` (`js:` プレフィックス)、素の HTML の `on*` ハンドラも同様。

golangci-lint / gosec は生成コードを除外し templ のセマンティクスも知らないため、
この領域は既存ツールの空白地帯になっている。templ-lint の指摘位置は生成された
Go コードではなく **`.templ` の行・列**を直接指す。

## インストール

```bash
go install github.com/taq25/templ-lint@latest
```

または [Releases](https://github.com/taq25/templ-lint/releases) からバイナリを取得。

## 使い方

```bash
templ-lint ./views                                     # 再帰的に *.templ を検査
templ-lint -allow-sanitizer sanitize.HTML ./views      # サニタイズラッパーを許可
templ-lint -format json -strict ./views                # JSON 出力 / WARNING も失敗扱い
```

| フラグ | 説明 |
|---|---|
| `-allow-sanitizer pkg.Func` | `templ.Raw(pkg.Func(x))` を許可 (繰り返し指定可) |
| `-htmx-prefix prefix` | htmx が `hx-` と同じに扱う追加の接頭辞 (`htmx.config.prefix`、例 `data-boost-`)。`data-hx-` は常に認識 (繰り返し指定可) |
| `-alpine-prefix prefix` | Alpine が `x-` と同じに扱う追加の接頭辞 (`Alpine.prefix`、例 `data-x-`)。`data-x-*` はふつうのデータ属性でもあるので既定では無効 (繰り返し指定可) |
| `-format text\|json` | 出力形式 (デフォルト text) |
| `-strict` | WARNING でも非ゼロ終了 |
| `-version` | バージョン表示 |

終了コード: `0` 検出なし / `1` 検出あり (WARNING のみは `-strict` 時) / `2` 実行エラー

## ルール

| ルール | 検知内容 | 重大度 |
|---|---|---|
| `js-eval-attr` | JS として評価される属性への動的値。HTML `on*` / Alpine の `x-*` (評価しないと確認済みのもの以外すべて)、`@*`, `:*` / htmx `hx-on`, `hx-on:*`, `hx-on::*`, `hx-on-*`, `hx-trigger` (イベントフィルタ), `hx-vars`。`hx-vals`, `hx-headers`, `hx-confirm`, `hx-request` は、値の先頭が `js:` になり得ない静的リテラルでなければ検知 | ERROR |
| `unsafe-url-attr` | templ が URL サニタイズ**しない**属性への動的 URL: `<iframe/frame/embed/script src>`、`formaction`、`<a>`/`<link>` 以外の `href` (`<area>`, `<base>`, SVG など)、`xlink:href`。templ がサニタイズするのは `a/link[href]`, `form[action]`, `object[data]` だけ。`templ.URL(x)` と自オリジンの相対パスは許可 | ERROR |
| `srcdoc-attr` | 動的な `srcdoc` (ブラウザが HTML 文書として解釈する)。`escape-bypass` と同じサニタイザ呼び出しは許可 | ERROR |
| `escape-bypass` | `templ.Raw` / `templ.SafeURL` / `templ.JSExpression` / `templ.JSUnsafeFuncCall` / `templ.SafeCSS` / `templ.SafeCSSProperty` への非リテラル引数。`{{ ... }}` やテンプレート外の Go コード、import の別名、関数を値として使う形 (`f := templ.Raw`) も検査 | ERROR |
| `dyn-attr-name` | 動的な属性名 (`{ name }={ value }`) | ERROR |
| `url-attr` | 動的なリクエスト先 (`hx-get/post/put/patch/delete/query`, `hx-action`) と履歴 URL (`hx-push-url`, `hx-replace-url`)。自オリジン確定の相対パス (先頭が `"/x…"` の文字列リテラル、例 `"/posts/" + id`) は除外。`//host` のプロトコル相対や変数由来の URL は検知 | WARNING |
| `unvetted-attr` | templ-lint が分類していない htmx 属性への動的値 (`hx-config`, `hx-status:*`, `hx-method`, 将来の htmx で増える属性など) | WARNING |
| `spread-attr` | スプレッド属性 (`{ attrs... }`) | WARNING |
| `unsafe-target-blank` | `target="_blank"` に `rel="noopener"` がない — reverse tabnabbing (CWE-1022) | WARNING |
| `missing-sri` | クロスオリジンの `<script>` / `<link rel=stylesheet>` に `integrity` がない — サプライチェーンリスク (CWE-353) | WARNING |
| `invalid-ignore` | 理由のない `templ-lint:ignore` | WARNING |

XSS 以外に、テンプレート構造から見える非 XSS の問題も検出する (reverse tabnabbing、
外部リソースの SRI 欠如)。ハンドラ側ロジックに存在する脆弱性 (SQL インジェクション、
認証、CSRF トークン検証) は `.templ` からは見えないため対象外。

### 属性名の正規化と許可リスト方式

分類の前に属性名を正規化し、表記揺れによる見逃しを防ぐ: 小文字化 (`onClick` = `onclick`)、
`data-hx-*` と `-htmx-prefix` / `-alpine-prefix` の接頭辞を `hx-*` / `x-*` に揃え、
htmx 4 の継承修飾子 (`:inherited`, `:append`, `-inherited` / `-append`) を取り除く。

htmx と Alpine の名前空間では「安全と確認済みの属性だけを除外する」許可リスト方式をとる。
未知の Alpine ディレクティブは JS を評価するもの (`js-eval-attr`)、未知の htmx 属性は
`unvetted-attr` として扱うので、将来のバージョンで属性が増えても黙って素通りしない。

- 評価しない Alpine ディレクティブ: `x-cloak`, `x-ref`, `x-transition*`, `x-ignore`,
  `x-teleport`, `x-collapse`, `x-mask` (`x-mask:dynamic` は評価する)
- 安全扱いの htmx 属性: `hx-swap`, `hx-swap-oob`, `hx-boost`, `hx-encoding`, `hx-preserve`,
  `hx-validate`, `hx-history`, `hx-history-elt`, `hx-prompt`, `hx-inherit`, `hx-disinherit`,
  `hx-params`, `hx-morph-skip*` と、セレクタを受け取る `hx-target`, `hx-include`, `hx-select`,
  `hx-select-oob`, `hx-indicator`, `hx-disable`, `hx-disabled-elt`, `hx-ignore`, `hx-sync`
  (動的なセレクタは XSS に至らず、`"#row-" + id` は日常的なコードのため)

文字列リテラルだけでできた値 (`x-init={ "load()" }`) は静的な属性と同じく開発者が書いたものなので、
属性値の規則の対象外。

### escape-bypass の例外

- `templ.Raw("<hr/>")` — 静的リテラルは許可
- `templ.Raw(bluemonday.UGCPolicy().Sanitize(x))` — bluemonday チェーンは常に許可
- `templ.Raw(sanitize.HTML(x))` — `-allow-sanitizer sanitize.HTML` 指定時のみ許可
- `p.Sanitize(x)` (変数に格納したポリシー) は**不許可** — AST では `p` の由来を
  検証できず、`Sanitize` という名前のメソッドなら何でも通る抜け穴になるため。
  チェーン形式か、bluemonday ポリシーを 1 箇所に集約したラッパー関数を使うこと

## 検出の抑制

誤検知には、同じ行または直前の行のコメントで**理由付き**の抑制を書く。
理由のないディレクティブは `invalid-ignore` として報告され、抑制効果を持たない。

```
// templ-lint:ignore js-eval-attr preset はサーバ側 enum から選択され、ユーザー入力ではない
<div x-init={ preset }>
```

HTML コメント形式 (`<!-- templ-lint:ignore ... -->`)、カンマ区切りの複数ルール指定も可。

## 仕組み

自前のパーサは持たず、公式パーサ 2 つを継ぎ合わせている:

1. templ の `parser/v2` が `.templ` を解析。静的 (`ConstantAttribute`) と
   動的 (`ExpressionAttribute`) を型レベルで区別し、Go 式は位置付き文字列として保持
2. 埋め込まれた Go 式は標準の `go/parser` で解析し、`templ.Raw` の引数判定
   (リテラル検出・サニタイザ許可リスト) を正規の Go AST 上で行う

templ コンパイラと同じパーサにリンクしているため、templ 更新で AST が変わると
**コンパイルエラーとして顕在化**する。go.mod の templ バージョンはアプリケーション側と揃えること。

ただしこれが保証するのは templ の構文だけで、属性の**意味**は htmx / Alpine が決めるため
パーサからは見えない。属性の追加・改名で静かに見逃さないための仕組みが、上記の許可リスト方式である。

## 制約と併用すべきランタイム対策

- 検査対象は `.templ` のみ。手書き `.go` 内の `templ.Raw` は対象外
- taint 追跡はしない。非リテラルは許可リスト外なら一律検知 (安全側の誤検知)
- 静的解析は実行時の値を見られないため、ランタイム側の無害化を併用する:
  [Alpine.js CSP ビルド](https://alpinejs.dev/advanced/csp)、`unsafe-eval` を
  含まない CSP ヘッダ、`htmx.config.allowEval = false`、
  `htmx.config.selfRequestsOnly = true` (htmx 2 でデフォルト)
