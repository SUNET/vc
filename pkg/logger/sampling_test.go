package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countRecords reads the log file and counts the lines whose message is
// msg, so a test can tell what survived sampling.
func countRecords(t *testing.T, path, msg string) int {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening the log file: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var record struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		if record.Msg == msg {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading the log file: %v", err)
	}
	return count
}

// zap's production config samples by (level, message) within a one-second
// window - the first 100 records, then one in 100 - and structured fields
// take no part in the decision. A burst of errors sharing one message is
// therefore mostly dropped, taking its req_id with it.
//
// That is fatal to what SUNET/vc#357 promises: the API hands a caller a
// request id INSTEAD of the cause, so an id that appears in no log line is
// worse than useless. 500 refusals in a burst must produce 500 error
// records.
func TestErrorRecordsAreNeverSampledAway(t *testing.T) {
	dir := t.TempDir()
	log, err := New("burst", dir, true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const burst = 500
	for i := range burst {
		log.Error(os.ErrPermission, "unclassified error", "req_id", i)
	}

	path := filepath.Join(dir, "burst.log")
	if got := countRecords(t, path, "unclassified error"); got != burst {
		t.Fatalf("logged %d of %d error records - a sampled error is a caller holding a request id that appears nowhere", got, burst)
	}
}

// The other half: sampling is still doing its job below error level, so
// this is an exemption rather than a quiet removal of flood protection.
func TestInfoRecordsAreStillSampled(t *testing.T) {
	dir := t.TempDir()
	log, err := New("burst", dir, true)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const burst = 500
	for range burst {
		log.Info("a repetitive info line")
	}

	path := filepath.Join(dir, "burst.log")
	got := countRecords(t, path, "a repetitive info line")
	if got >= burst {
		t.Fatalf("logged %d of %d info records - sampling should still thin a repetitive info burst", got, burst)
	}
	if got == 0 {
		t.Fatalf("logged none of %d info records - sampling keeps the first 100", burst)
	}
}

// A development logger samples nothing, and the wrapper must not change
// that.
func TestDevelopmentLoggerSamplesNothing(t *testing.T) {
	dir := t.TempDir()
	log, err := New("dev", dir, false)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const burst = 300
	for range burst {
		log.Info("a repetitive info line")
	}

	// The development encoder is console, not JSON, so count by substring.
	data, err := os.ReadFile(filepath.Join(dir, "dev.log"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "a repetitive info line"); got != burst {
		t.Fatalf("logged %d of %d records - the development logger samples nothing", got, burst)
	}
}
