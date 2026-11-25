// bluemonday を import していないファイルは検査しない。
package policy

type other struct{}

func (other) AllowDataAttributes() {}

func use() { other{}.AllowDataAttributes() }
