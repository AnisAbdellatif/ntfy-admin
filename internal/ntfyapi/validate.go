package ntfyapi

import (
	"regexp"
	"slices"
	"strings"
)

// Mirrors ntfy user/util.go.
var (
	usernameRegex     = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]+$`)
	topicRegex        = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)
	topicPatternRegex = regexp.MustCompile(`^[-_*A-Za-z0-9]{1,64}$`)
	tierRegex         = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)
)

// ValidUsername reports whether s is a valid ntfy username (not including "*").
func ValidUsername(s string) bool { return usernameRegex.MatchString(s) }

// ValidACLUsername is ValidUsername plus the special anonymous user "*".
func ValidACLUsername(s string) bool { return s == Everyone || ValidUsername(s) }

// ValidTopic reports whether s is a valid exact topic name.
func ValidTopic(s string) bool { return topicRegex.MatchString(s) }

// ValidTopicPattern reports whether s is a valid topic or topic pattern for ACL entries.
func ValidTopicPattern(s string) bool { return topicPatternRegex.MatchString(s) }

// ValidTier reports whether s is a valid tier code.
func ValidTier(s string) bool { return tierRegex.MatchString(s) }

// ValidPermission reports whether s is one of the canonical permission strings.
func ValidPermission(s string) bool { return slices.Contains(Permissions, s) }

// IsPattern reports whether the topic string contains a wildcard.
func IsPattern(topic string) bool { return strings.Contains(topic, "*") }

// MatchTopic reports whether the exact topic matches the ACL pattern, using the
// same semantics as ntfy ('*' matches any sequence, everything else is literal).
func MatchTopic(pattern, topic string) bool {
	re, err := regexp.Compile("^" + strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*") + "$")
	if err != nil {
		return false
	}
	return re.MatchString(topic)
}

// MaskToken shortens a token for display and logs: "tk_abcd…wxyz".
func MaskToken(t string) string {
	if len(t) <= 12 {
		return "tk_…"
	}
	return t[:7] + "…" + t[len(t)-4:]
}
