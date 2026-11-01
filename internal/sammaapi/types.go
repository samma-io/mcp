package sammaapi

import "time"

// Wire types for the samma app read API (/api/v1). They mirror the JSON
// returned by samma-io/app; unknown fields are ignored.

type Organisation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type TokenMeta struct {
	Name     string `json:"name"`
	ReadOnly bool   `json:"readOnly"`
}

// Me is GET /api/v1/me.
type Me struct {
	Organisation Organisation `json:"organisation"`
	Token        TokenMeta    `json:"token"`
}

type ProfileRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // FULL | SMALL
}

type Target struct {
	ID                 string     `json:"id"`
	Value              string     `json:"value"`
	Type               string     `json:"type"` // ip | dns
	Label              *string    `json:"label,omitempty"`
	Port               *int       `json:"port,omitempty"`
	Profile            ProfileRef `json:"profile"`
	ScannerStatus      string     `json:"scannerStatus"`
	ReachabilityStatus string     `json:"reachabilityStatus"`
	CreatedAt          time.Time  `json:"createdAt"`
}

// TargetList is GET /api/v1/targets.
type TargetList struct {
	Targets    []Target `json:"targets"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

// ScannerRun summarises the latest run of one scanner against a target.
type ScannerRun struct {
	Scanner      string         `json:"scanner"`
	RunID        string         `json:"runId,omitempty"`
	Outcome      string         `json:"outcome,omitempty"`
	FinishedAt   *time.Time     `json:"finishedAt,omitempty"`
	LastSeenAt   *time.Time     `json:"lastSeenAt,omitempty"`
	FindingCount int            `json:"findingCount"`
	Severity     map[string]int `json:"severity,omitempty"`
}

// TargetDetail is GET /api/v1/targets/{id}.
type TargetDetail struct {
	Target   Target       `json:"target"`
	Scanners []ScannerRun `json:"scanners"`
}

type Endpoint struct {
	Host   string `json:"host,omitempty"`
	Port   any    `json:"port,omitempty"`
	Scheme string `json:"scheme,omitempty"`
}

// Finding is one scan_results row, flattened from the finding-v2 message.
type Finding struct {
	Time        time.Time `json:"time"`
	TargetID    string    `json:"targetId"`
	Target      string    `json:"target,omitempty"`
	Scanner     string    `json:"scanner"`
	RunID       string    `json:"runId,omitempty"`
	CheckID     string    `json:"checkId,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Title       string    `json:"title,omitempty"`
	Host        string    `json:"host,omitempty"`
	Port        string    `json:"port,omitempty"`
	Status      string    `json:"status,omitempty"`
	Type        string    `json:"type,omitempty"`
	Endpoint    *Endpoint `json:"endpoint,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	References  []string  `json:"references,omitempty"`
	CveIDs      []string  `json:"cveIds,omitempty"`
	Compliance  []string  `json:"compliance,omitempty"`
}

// Results is GET /api/v1/targets/{id}/results.
type Results struct {
	TargetID string       `json:"targetId"`
	Runs     []ScannerRun `json:"runs"`
	Results  []Finding    `json:"results"`
}

// FindingList is GET /api/v1/findings.
type FindingList struct {
	Findings []Finding `json:"findings"`
}
