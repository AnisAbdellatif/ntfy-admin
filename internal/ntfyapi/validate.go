package ntfyapi

import (
	"regexp"
	"slices"
	"strings"
)

// Mirrors ntfy user/util.go.
var (
	usernameRegex     = regexp.MustCompile(`^[-_.+@a-zA-Z0-9]+$`)
	topicPatternRegex = regexp.MustCompile(`^[-_*A-Za-z0-9]{1,64}$`)
)

// ValidUsername reports whether s is a valid ntfy username (not including "*").
func ValidUsername(s string) bool { return usernameRegex.MatchString(s) }

// ValidACLUsername is ValidUsername plus the special anonymous user "*".
func ValidACLUsername(s string) bool { return s == Everyone || ValidUsername(s) }

// ValidTopicPattern reports whether s is a valid topic or topic pattern for ACL entries.
func ValidTopicPattern(s string) bool { return topicPatternRegex.MatchString(s) }

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

// EffectiveAccess returns which of grants decides access to the exact topic,
// using ntfy's order: the longest matching topic string wins, and on a tie
// the rule with write access. found is false when no grant matches, in which
// case ntfy falls back to auth-default-access. Pass the grants of one user
// (e.g. those of "*" for anonymous access).
func EffectiveAccess(grants []Grant, topic string) (g Grant, found bool) {
	for _, c := range grants {
		if !MatchTopic(c.Topic, topic) {
			continue
		}
		if !found || len(c.Topic) > len(g.Topic) || (len(c.Topic) == len(g.Topic) && canWrite(c.Permission) && !canWrite(g.Permission)) {
			g, found = c, true
		}
	}
	return g, found
}

func canWrite(perm string) bool { return perm == PermReadWrite || perm == PermWriteOnly }

// MaskToken shortens a token for display and logs: "tk_abcd…wxyz".
func MaskToken(t string) string {
	if len(t) <= 12 {
		return "tk_…"
	}
	return t[:7] + "…" + t[len(t)-4:]
}
