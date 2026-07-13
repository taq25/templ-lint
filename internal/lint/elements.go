package lint

import (
	"fmt"
	"strings"

	parser "github.com/a-h/templ/parser/v2"
)

// checkElement は要素レベル (属性の組み合わせ) の規則を検査する。
// XSS 系の属性単体ルールとは別に、以下の非 XSS 脆弱性クラスを扱う:
//   - unsafe-target-blank: reverse tabnabbing (CWE-1022)
//   - missing-sri:         外部リソースの Subresource Integrity 欠如 (CWE-353)
func (l *Linter) checkElement(path string, n *parser.Element, findings *[]Finding) {
	name := strings.ToLower(n.Name)

	// reverse tabnabbing: target="_blank" のリンクは rel に noopener / noreferrer が
	// ないと、開いた先のページが window.opener 経由で元タブを操作できる。
	if name == "a" || name == "area" || name == "form" {
		if v, ok := constAttr(n.Attributes, "target"); ok && strings.EqualFold(v, "_blank") {
			rel, _ := constAttr(n.Attributes, "rel")
			if !relHasToken(rel, "noopener") && !relHasToken(rel, "noreferrer") {
				*findings = append(*findings, Finding{
					File: path, Line: n.Range.From.Line + 1, Col: n.Range.From.Col + 1,
					Rule: RuleTabnabbing, Severity: SeverityWarning,
					Message: `target="_blank" without rel="noopener": the opened page can control this tab via window.opener (reverse tabnabbing). Add rel="noopener noreferrer"`,
				})
			}
		}
	}

	// <link rel=stylesheet> の SRI。<script> は ScriptElement ノードなので checkScript が扱う。
	if name == "link" {
		if rel, _ := constAttr(n.Attributes, "rel"); relHasToken(rel, "stylesheet") {
			if href, ok := constAttr(n.Attributes, "href"); ok && isCrossOrigin(href) {
				if _, has := constAttr(n.Attributes, "integrity"); !has {
					*findings = append(*findings, sriFinding(path, n.Range, "link", "href"))
				}
			}
		}
	}
}

// checkScript は <script> 要素 (専用の ScriptElement ノード) の SRI を検査する。
// クロスオリジンの src は integrity 属性がないと CDN 改ざんで任意コードを読み込まされる。
func (l *Linter) checkScript(path string, n *parser.ScriptElement, findings *[]Finding) {
	if src, ok := constAttr(n.Attributes, "src"); ok && isCrossOrigin(src) {
		if _, has := constAttr(n.Attributes, "integrity"); !has {
			*findings = append(*findings, sriFinding(path, n.Range, "script", "src"))
		}
	}
}

func sriFinding(path string, r parser.Range, tag, urlAttr string) Finding {
	return Finding{
		File: path, Line: r.From.Line + 1, Col: r.From.Col + 1,
		Rule: RuleMissingSRI, Severity: SeverityWarning,
		Message: fmt.Sprintf(
			"cross-origin <%s %s> has no integrity attribute: a compromised CDN can serve arbitrary code. Add a Subresource Integrity hash",
			tag, urlAttr),
	}
}

// constAttr は属性スライスから静的な属性値を返す。存在しない/動的な場合は ok=false。
func constAttr(attrs []parser.Attribute, key string) (string, bool) {
	for _, a := range attrs {
		ca, ok := a.(*parser.ConstantAttribute)
		if !ok {
			continue
		}
		if strings.EqualFold(ca.Key.String(), key) {
			return ca.Value, true
		}
	}
	return "", false
}

func relHasToken(rel, token string) bool {
	for _, f := range strings.Fields(rel) {
		if strings.EqualFold(f, token) {
			return true
		}
	}
	return false
}

// isCrossOrigin は URL が別オリジンを指し得るか (絶対 URL / プロトコル相対) を判定する。
// 相対パス (/x.js, ./x.js) は同一オリジンなので対象外。
func isCrossOrigin(url string) bool {
	return strings.HasPrefix(url, "http://") ||
		strings.HasPrefix(url, "https://") ||
		strings.HasPrefix(url, "//")
}
