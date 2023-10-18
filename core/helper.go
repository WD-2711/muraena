package core

type iError interface {
	IsError() bool
}

// IsError
// https://mikeschinkel.me/2019/gos-unfortunate-err-nil-idiom/
func IsError(err error) bool {
	if err == nil {
		return false
	}

	ei, ok := err.(iError)
	if !ok {
		return true
	}

	return ei.IsError()
}

// StringContains 查看 v 是否在 a 的字符串数组中
func StringContains(v string, a []string) bool {
	for _, i := range a {
		if i == v {
			return true
		}
	}
	return false
}
