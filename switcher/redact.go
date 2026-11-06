package switcher

import (
	"net/url"
	"regexp"
)

// RedactURL returns u as a string without its userinfo, so log lines and
// status output never leak proxy passwords.
func RedactURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	cp := *u
	cp.User = nil
	return cp.String()
}

// userinfoRE matches the credentials part of a URL embedded in free-form
// text. The password may contain characters url.Parse rejects, which is
// exactly when a raw URL ends up inside an error message.
var userinfoRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s"'@]+@`)

// RedactText removes URL credentials from arbitrary text. url.Parse and
// net/http errors quote the URL they failed on, so any error that may
// mention a proxy must pass through here before being logged or returned.
func RedactText(s string) string {
	return userinfoRE.ReplaceAllString(s, "${1}")
}

// redactedError hides URL credentials in Error() while keeping the original
// error reachable for errors.Is and errors.As.
type redactedError struct{ err error }

func (e *redactedError) Error() string { return RedactText(e.err.Error()) }
func (e *redactedError) Unwrap() error { return e.err }

// redactErr wraps err so that its message cannot leak URL credentials.
func redactErr(err error) error {
	if err == nil {
		return nil
	}
	return &redactedError{err: err}
}
