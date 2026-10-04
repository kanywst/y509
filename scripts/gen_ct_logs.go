//go:build ignore

// Package main refreshes the bundled Certificate Transparency log list.
//
// It reads Google's all_logs_list.json, the list Chrome's CT policy is built
// on, and keeps only what y509 shows next to an SCT: which log, run by whom,
// and in what state. The result is committed, so naming a log never needs the
// network. Run it with `make ct-logs` when logs are added or retired.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"time"
)

const source = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

type logEntry struct {
	Description string                     `json:"description"`
	LogID       string                     `json:"log_id"`
	State       map[string]json.RawMessage `json:"state"`
}

type upstream struct {
	Version   string `json:"version"`
	Timestamp string `json:"log_list_timestamp"`
	Operators []struct {
		Name      string     `json:"name"`
		Logs      []logEntry `json:"logs"`
		TiledLogs []logEntry `json:"tiled_logs"`
	} `json:"operators"`
}

// Log is one entry of the bundled list.
type Log struct {
	ID          string `json:"id"`
	Description string `json:"description,omitempty"`
	Operator    string `json:"operator"`
	State       string `json:"state,omitempty"`
}

// Bundle is the committed file.
type Bundle struct {
	Source    string `json:"source"`
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	Logs      []Log  `json:"logs"`
}

func main() {
	out := "pkg/certificate/ctlogs.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source)
	if err != nil {
		log.Fatalf("fetching %s: %v", source, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("fetching %s: %s", source, resp.Status)
	}

	var list upstream
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		log.Fatalf("decoding the log list: %v", err)
	}

	bundle := Bundle{Source: source, Version: list.Version, Timestamp: list.Timestamp}
	for _, op := range list.Operators {
		for _, entries := range [][]logEntry{op.Logs, op.TiledLogs} {
			for _, l := range entries {
				bundle.Logs = append(bundle.Logs, Log{
					ID:          l.LogID,
					Description: l.Description,
					Operator:    op.Name,
					State:       stateName(l.State),
				})
			}
		}
	}
	// Sorted so a refresh diffs as the logs that actually changed.
	sort.Slice(bundle.Logs, func(i, j int) bool { return bundle.Logs[i].ID < bundle.Logs[j].ID })

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d logs (list %s, %s) to %s\n", len(bundle.Logs), list.Version, list.Timestamp, out)
}

// stateName is the single key of the log's state object: usable, qualified,
// readonly, retired, rejected or pending.
func stateName(state map[string]json.RawMessage) string {
	for name := range state {
		return name
	}
	return ""
}
