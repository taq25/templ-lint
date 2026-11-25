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
	RuleUnvettedAttr  = "unvetted-attr"       // 安全性を確認していない htmx 属性への動的値
	RuleUnsafeURLAttr = "unsafe-url-attr"     // templ が URL サニタイズしない属性への動的 URL
	RuleSrcdocAttr    = "srcdoc-attr"         // iframe srcdoc (HTML として解釈される) への動的値

	RuleHTMXConfigMeta       = "htmx-config-meta"       // <meta name="htmx-config"> への動的値
	RuleHTMXDisableSemantics = "htmx-disable-semantics" // htmx 2/4 で意味が入れ替わった hx-disable / hx-ignore

	// -csp strict のときだけ有効な互換性の検査 (strict CSP の下で動かない書き方)
	RuleCSPInlineHandler = "csp-inline-handler" // インラインのイベントハンドラ / javascript: URL
	RuleCSPEvalAttr      = "csp-eval-attr"      // htmx が eval で評価する属性 (hx-on, hx-trigger のフィルタ, js:)
	RuleCSPInlineScript  = "csp-inline-script"  // nonce のないインライン <script> / 静的な nonce

	RuleUnusedIgnore    = "unused-ignore"    // 何も抑制していない templ-lint:ignore
	RuleSanitizerPolicy = "sanitizer-policy" // htmx / Alpine / イベント属性を通す bluemonday ポリシー
)

// RuleInfo はルールの説明 (SARIF の rules や ignore の検証に使う)。
type RuleInfo struct {
	ID          string
	Severity    Severity
	Description string
}

// Rules は templ-lint の全ルール。新しいルールを足したらここにも加える。
var Rules = []RuleInfo{
	{RuleJSEvalAttr, SeverityError, "Dynamic value in an attribute that Alpine.js, htmx or the browser evaluates as JavaScript"},
	{RuleURLAttr, SeverityWarning, "Dynamic URL in an htmx request attribute (hx-get, hx-post, ...)"},
	{RuleUnvettedAttr, SeverityWarning, "Dynamic value in an htmx attribute that templ-lint has not classified"},
	{RuleUnsafeURLAttr, SeverityError, "Dynamic URL in an attribute that templ does not sanitize (iframe src, formaction, ...)"},
	{RuleSrcdocAttr, SeverityError, "Dynamic value in iframe srcdoc, which is parsed as an HTML document"},
	{RuleEscapeBypass, SeverityError, "Non-literal value passed to a templ function that bypasses escaping (templ.Raw, templ.SafeURL, ...)"},
	{RuleDynAttrName, SeverityError, "Dynamic attribute name"},
	{RuleSpreadAttr, SeverityWarning, "Spread attributes whose names are decided at runtime"},
	{RuleHTMXConfigMeta, SeverityError, `Dynamic content in <meta name="htmx-config">`},
	{RuleHTMXDisableSemantics, SeverityError, "hx-disable / hx-ignore used with the meaning of the other htmx major version"},
	{RuleTabnabbing, SeverityWarning, `target="_blank" without rel="noopener" (reverse tabnabbing)`},
	{RuleMissingSRI, SeverityWarning, "Cross-origin script or stylesheet without Subresource Integrity"},
	{RuleSanitizerPolicy, SeverityWarning, "bluemonday policy that lets htmx, Alpine.js or event handler attributes through"},
	{RuleCSPInlineHandler, SeverityWarning, "Inline event handler or javascript: URL that a strict CSP blocks"},
	{RuleCSPEvalAttr, SeverityWarning, "htmx attribute value evaluated with eval, which a strict CSP blocks"},
	{RuleCSPInlineScript, SeverityWarning, "Inline <script> without a per-response nonce"},
	{RuleInvalidIgnore, SeverityWarning, "templ-lint:ignore directive without a reason or with an unknown rule"},
	{RuleUnusedIgnore, SeverityWarning, "templ-lint:ignore directive that suppresses nothing"},
}

var rulesByID = func() map[string]RuleInfo {
	m := make(map[string]RuleInfo, len(Rules))
	for _, r := range Rules {
		m[r.ID] = r
	}
	return m
}()

// IsKnownRule はルール ID が存在するかを返す。
func IsKnownRule(id string) bool {
	_, ok := rulesByID[id]
	return ok
}
