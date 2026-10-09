package web

import (
	"net/http"
	"slices"
	"strings"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

// matrixCap limits the users × topics grid; past this it is truncated.
const matrixCap = 50

type topicEntry struct {
	Username   string
	Permission string
	IsSvc      bool
}

type topicRow struct {
	Topic     string
	IsPattern bool
	Entries   []topicEntry
	Public    string   // permission of "*" on this exact ACL entry, if any
	MatchedBy []string // for exact topics: patterns that also match it
}

type matrixRow struct {
	Username string
	Cells    []string // permission per topic column, "" = no rule
}

type topicsView struct {
	Topics    []topicRow
	Grantable []string // users that can be granted access (non-admins incl. "*")
	Matrix    bool
	Columns   []string
	Rows      []matrixRow
	Truncated bool
}

// buildTopics inverts GET /v1/users into one row per distinct ACL topic string.
func (s *Server) buildTopics(users []ntfyapi.User) []topicRow {
	byTopic := map[string]*topicRow{}
	for _, u := range users {
		for _, g := range u.Grants {
			row, ok := byTopic[g.Topic]
			if !ok {
				row = &topicRow{Topic: g.Topic, IsPattern: ntfyapi.IsPattern(g.Topic)}
				byTopic[g.Topic] = row
			}
			row.Entries = append(row.Entries, topicEntry{Username: u.Username, Permission: g.Permission, IsSvc: s.isSvc(u.Username)})
			if u.Username == ntfyapi.Everyone {
				row.Public = g.Permission
			}
		}
	}
	var patterns []string
	rows := make([]topicRow, 0, len(byTopic))
	for _, row := range byTopic {
		slices.SortFunc(row.Entries, func(a, b topicEntry) int {
			if a.Username == ntfyapi.Everyone {
				return -1
			} else if b.Username == ntfyapi.Everyone {
				return 1
			}
			return strings.Compare(a.Username, b.Username)
		})
		if row.IsPattern {
			patterns = append(patterns, row.Topic)
		}
		rows = append(rows, *row)
	}
	slices.Sort(patterns)
	for i := range rows {
		if rows[i].IsPattern {
			continue
		}
		for _, p := range patterns {
			if ntfyapi.MatchTopic(p, rows[i].Topic) {
				rows[i].MatchedBy = append(rows[i].MatchedBy, p)
			}
		}
	}
	slices.SortFunc(rows, func(a, b topicRow) int { return strings.Compare(a.Topic, b.Topic) })
	return rows
}

func (s *Server) handleTopics(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	users, err := s.fetchUsers(r.Context(), sess)
	if err != nil {
		s.pageFailed(w, r, sess, err)
		return
	}
	sortUsers(users)
	view := topicsView{Topics: s.buildTopics(users), Matrix: r.URL.Query().Get("view") == "matrix"}
	for _, u := range users {
		if !u.IsAdmin() {
			view.Grantable = append(view.Grantable, u.Username)
		}
	}
	if view.Matrix {
		cols := view.Topics
		if len(cols) > matrixCap {
			cols, view.Truncated = cols[:matrixCap], true
		}
		for _, t := range cols {
			view.Columns = append(view.Columns, t.Topic)
		}
		for _, u := range users {
			if u.IsAdmin() {
				continue
			}
			if len(view.Rows) == matrixCap {
				view.Truncated = true
				break
			}
			row := matrixRow{Username: u.Username, Cells: make([]string, len(cols))}
			for i, c := range view.Columns {
				for _, g := range u.Grants {
					if g.Topic == c {
						row.Cells[i] = g.Permission
					}
				}
			}
			view.Rows = append(view.Rows, row)
		}
	}
	s.render(w, r, sess, "topics", "Topics", view)
}

func topicBack(topic string) string {
	if ntfyapi.ValidTopicPattern(topic) {
		return "/topics#t-" + topic
	}
	return "/topics"
}

func (s *Server) handleTopicGrant(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	topic := strings.TrimSpace(r.PostForm.Get("topic"))
	s.grant(w, r, sess, r.PostForm.Get("username"), topic, r.PostForm.Get("permission"), topicBack(topic))
}

func (s *Server) handleTopicRevoke(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	topic := r.PostForm.Get("topic")
	s.revoke(w, r, sess, r.PostForm.Get("username"), topic, topicBack(topic))
}

func (s *Server) handleTopicPublic(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	topic := r.PostForm.Get("topic")
	s.grant(w, r, sess, ntfyapi.Everyone, topic, ntfyapi.PermReadOnly, topicBack(topic))
}

func (s *Server) handleTopicPrivate(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	topic := r.PostForm.Get("topic")
	s.revoke(w, r, sess, ntfyapi.Everyone, topic, topicBack(topic))
}
