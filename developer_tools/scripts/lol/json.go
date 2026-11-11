package main

import (
	"encoding/json"
	"os"
	"time"
)

type signerResult struct {
	State   string `json:"state"` // ok, failed or not_checked
	Subject string `json:"subject,omitempty"`
	Error   string `json:"error,omitempty"`
}

func (s signerResult) text() string {
	switch s.State {
	case "ok":
		return paint(colorGreen, "signature ok") + " " + s.Subject
	case "failed":
		return paint(colorRed, "FAIL") + " " + s.Error
	}
	return paint(colorYellow, "not checked (no -anchors)")
}

type jsonEntry struct {
	Index     int        `json:"index"`
	State     string     `json:"state"`
	Kind      string     `json:"kind,omitempty"`
	Operator  string     `json:"operator,omitempty"`
	Territory string     `json:"territory,omitempty"`
	Type      string     `json:"type,omitempty"`
	Format    string     `json:"format,omitempty"`
	URL       string     `json:"url"`
	Signature string     `json:"signature"`
	NextDate  *time.Time `json:"nextUpdate,omitempty"`
	DaysLeft  *int       `json:"daysLeft,omitempty"` // negative once expired
	Detail    string     `json:"detail,omitempty"`
}

type jsonReport struct {
	URL        string       `json:"url"`
	CheckedAt  time.Time    `json:"checkedAt"`
	Type       string       `json:"type"`
	Issued     string       `json:"issued"`
	NextUpdate string       `json:"nextUpdate"`
	Signer     signerResult `json:"signer"`
	Lists      []jsonEntry  `json:"lists"`
	Summary    struct {
		OK     int `json:"ok"`
		Stale  int `json:"stale"`
		Failed int `json:"failed"`
	} `json:"summary"`
}

func writeJSON(url string, info schemeInfo, signer signerResult, rows []row, counts map[string]int, now time.Time) {
	rep := jsonReport{
		URL:        url,
		CheckedAt:  now.UTC(),
		Type:       info.LoTEType,
		Issued:     info.ListIssueDateTime,
		NextUpdate: info.NextUpdate,
		Signer:     signer,
		Lists:      make([]jsonEntry, 0, len(rows)),
	}
	rep.Summary.OK = counts["OK"]
	rep.Summary.Stale = counts["STALE"]
	rep.Summary.Failed = counts["FAIL"]

	for _, r := range rows {
		e := jsonEntry{
			Index:     r.n,
			State:     map[string]string{"OK": "ok", "STALE": "stale", "FAIL": "failed"}[r.res.state],
			Kind:      r.res.kind,
			Operator:  r.operator,
			Territory: r.territory,
			Type:      r.typeURI,
			Format:    r.format,
			URL:       r.location,
			Signature: map[string]string{"ok": "ok", "FAIL": "failed", "-": "not_checked"}[r.res.sig],
			Detail:    r.res.detail,
		}
		if !r.res.next.IsZero() {
			next := r.res.next.UTC()
			days := int(r.res.next.Sub(now).Hours() / 24)
			e.NextDate, e.DaysLeft = &next, &days
		}
		rep.Lists = append(rep.Lists, e)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fatal(err)
	}
}
