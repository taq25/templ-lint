package lint

// Severity は検出結果の重大度。
type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
)

// Finding は 1 件の検出結果。位置は .templ ファイル上の 1 始まりの行・列。
type Finding struct {
	File     string   `json:"file"`
	Line     uint32   `json:"line"`
	Col      uint32   `json:"col"`
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// ルール ID
const (
	RuleJSEvalAttr    = "js-eval-attr"        // HTML on*/Alpine/htmx が JS として評価する属性への動的値
	RuleURLAttr       = "url-attr"            // hx-get 等リクエスト先になる属性への動的値
	RuleSpreadAttr    = "spread-attr"         // { attrs... } による動的な属性名
	RuleEscapeBypass  = "escape-bypass"       // templ.Raw / templ.SafeURL 等への非リテラル
	RuleDynAttrName   = "dyn-attr-name"       // { name }={ value } 形式の動的属性名
	RuleTabnabbing    = "unsafe-target-blank" // target=_blank に rel=noopener がない
	RuleMissingSRI    = "missing-sri"         // 外部リソースに integrity 属性がない
	RuleInvalidIgnore = "invalid-ignore"      // 理由のない templ-lint:ignore ディレクティブ
)
