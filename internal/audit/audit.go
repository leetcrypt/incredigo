// Package audit writes an append-only, secret-redacted record of what incredigo
// found and did. It never logs secret material — only metadata already known to
// be non-secret (source, kind, redacted identity, location, action, outcome).
package audit

import (
	"encoding/json"
	"io"
	"os"
	"time"
)

type Entry struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"` // "scan" | "migrate" | "status" | "export" | "import"
	Source   string    `json:"source,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	Identity string    `json:"identity,omitempty"` // already redacted upstream
	Location string    `json:"location,omitempty"`
	Outcome  string    `json:"outcome,omitempty"`  // "ok" | "skipped" | error string
}

type Log struct {
	w   io.WriteCloser
	now func() time.Time
}

// Open appends to path. An empty path yields a no-op log. clock supplies entry
// timestamps (defaults to time.Now when nil) and is injectable for tests.
func Open(path string, clock func() time.Time) (*Log, error) {
	if clock == nil {
		clock = time.Now
	}
	if path == "" {
		return &Log{now: clock}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{w: f, now: clock}, nil
}

// Write appends one JSON-lines entry. Caller is responsible for keeping Identity
// redacted; this package does not inspect or sanitize values.
func (l *Log) Write(e Entry) error {
	if l.w == nil {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = l.w.Write(b)
	return err
}

func (l *Log) Close() error {
	if l.w == nil {
		return nil
	}
	return l.w.Close()
}
