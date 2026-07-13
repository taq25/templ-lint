# templ-lint

[a-h/templ](https://github.com/a-h/templ) の `.templ` ファイルを `parser/v2` で直接解析し、
htmx / Alpine.js 利用時に XSS へつながる危険な記述を検出するリンタ。

## 背景

templ はテキスト補間・属性値を HTML エスケープするが、**Alpine.js
(`x-data`, `x-init`, `@click`, `x-on:*` 等) と htmx (`hx-on:*`, `hx-vals`,
`hx-headers`) は属性値の文字列をそのまま JavaScript として評価する**。
そのため次のコードはエスケープされていても XSS になる:

```
<div x-init={ userInput }>   // userInput がそのまま eval される
```

この領域は既存の静的解析ツール (golangci-lint / gosec / templ 本体の LSP) では
カバーされていない。本ツールは `.templ` を templ 公式のパーサで直接解析するため、
生成コード (`*_templ.go`) の形式に依存せず、指摘位置も `.templ` の行・列を直接指す。

## ルール

| ルール ID | 内容 | 重大度 |
|---|---|---|
| `js-eval-attr` | JS として評価される属性 (`x-data`, `x-init`, `x-html`, `x-text`, `x-show`, `x-if`, `x-for`, `x-effect`, `x-on:*`, `@*`, `:*`, `x-model*`, `hx-on:*`, `hx-vals`, `hx-headers`) への動的値 | ERROR |
| `escape-bypass` | `templ.Raw` / `templ.SafeURL` / `templ.JSExpression` / `templ.JSUnsafeFuncCall` への非リテラル引数。`{{ ... }}` の Go コード片内も検査する | ERROR |
| `dyn-attr-name` | 動的な属性名 (`{ name }={ value }`)。名前ごと攻撃者が選べるとイベントハンドラを注入できる | ERROR |
| `url-attr` | リクエスト先になる属性 (`hx-get/post/put/patch/delete`) への動的値。サーバ側の許可リスト検証を促す | WARNING |
| `spread-attr` | スプレッド属性 (`{ attrs... }`)。属性名も値も動的になる | WARNING |

### escape-bypass の例外 (許可される形)

| 書き方 | 判定 |
|---|---|
| `templ.Raw("<hr/>")` | 許可 (静的リテラル) |
| `templ.Raw(bluemonday.UGCPolicy().Sanitize(x))` | 許可 (bluemonday チェーンは常に許可) |
| `templ.Raw(sanitize.HTML(x))` | `-allow-sanitizer sanitize.HTML` 指定時のみ許可 |
| `templ.Raw(p.Sanitize(x))` (変数のポリシー) | 不許可 (AST では由来を検証できないため。チェーンかラッパーに寄せる) |

サニタイズラッパーの推奨実装 (ポリシー構築は 1 回、レビュー対象を 1 ファイルに集約):

```go
// internal/sanitize/sanitize.go
package sanitize

import "github.com/microcosm-cc/bluemonday"

var ugc = bluemonday.UGCPolicy()

func HTML(s string) string { return ugc.Sanitize(s) }
```

## 使い方

```bash
go install github.com/taq25/templ-lint@latest

# ディレクトリを再帰的に検査 (*.templ を収集)
templ-lint ./views

# サニタイズラッパーを許可して検査
templ-lint -allow-sanitizer sanitize.HTML ./views

# JSON 出力 / WARNING も失敗扱い
templ-lint -format json -strict ./views
```

終了コード: `0` = 問題なし / `1` = 検出あり (WARNING のみの場合は `-strict` 時のみ) / `2` = 実行エラー

### CI (GitHub Actions)

```yaml
- run: go run github.com/taq25/templ-lint@latest -allow-sanitizer sanitize.HTML ./views
```

## 静的検知と併用すべきランタイム対策

すり抜けに備え、攻撃クラス自体を潰す設定を併用すること:

- **Alpine.js CSP ビルド** (`@alpinejs/csp`): 属性値の文字列 eval を廃止したビルド
- **CSP ヘッダ**: `script-src` から `unsafe-eval` を除外
- `htmx.config.allowEval = false`, `htmx.config.selfRequestsOnly = true` (htmx 2 でデフォルト)

## 開発

```bash
go test ./...   # testdata/dangerous.templ (11 件検出) / safe.templ (0 件) で検証
go build .
```

templ のバージョンは go.mod でアプリ本体と揃えること。parser/v2 の API が
変わった場合はコンパイルエラーとして顕在化する (静かな偽陰性は起きない)。
