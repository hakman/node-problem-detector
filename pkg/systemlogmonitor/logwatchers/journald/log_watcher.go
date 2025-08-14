/*
Copyright 2016 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package journald

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"

	"k8s.io/node-problem-detector/pkg/systemlogmonitor/logwatchers/types"
	logtypes "k8s.io/node-problem-detector/pkg/systemlogmonitor/types"
	"k8s.io/node-problem-detector/pkg/util"
	"k8s.io/node-problem-detector/pkg/util/tomb"
)

// journaldWatcher is the log watcher for journald using journalctl binary.
type journaldWatcher struct {
	cmd       *exec.Cmd
	cfg       types.WatcherConfig
	startTime time.Time
	logCh     chan *logtypes.Log
	tomb      *tomb.Tomb
	cancel    context.CancelFunc
}

// JournalEntry represents a journal entry from journalctl JSON output
type JournalEntry struct {
	Message                 string `json:"MESSAGE"`
	Timestamp               string `json:"__REALTIME_TIMESTAMP"`
	SyslogIdentifier        string `json:"SYSLOG_IDENTIFIER"`
	SourceRealtimeTimestamp string `json:"_SOURCE_REALTIME_TIMESTAMP"`
}

// NewJournaldWatcher is the create function of journald watcher.
func NewJournaldWatcher(cfg types.WatcherConfig) types.LogWatcher {
	uptime, err := util.GetUptimeDuration()
	if err != nil {
		klog.Fatalf("failed to get uptime: %v", err)
	}
	startTime, err := util.GetStartTime(time.Now(), uptime, cfg.Lookback, cfg.Delay)
	if err != nil {
		klog.Fatalf("failed to get start time: %v", err)
	}

	return &journaldWatcher{
		cfg:       cfg,
		startTime: startTime,
		tomb:      tomb.NewTomb(),
		// A capacity 1000 buffer should be enough
		logCh: make(chan *logtypes.Log, 1000),
	}
}

// Make sure NewJournaldWatcher is types.WatcherCreateFunc .
var _ types.WatcherCreateFunc = NewJournaldWatcher

// Watch starts the journal watcher.
func (j *journaldWatcher) Watch() (<-chan *logtypes.Log, error) {
	cmd, err := j.createJournalctlCommand()
	if err != nil {
		return nil, err
	}
	j.cmd = cmd
	go j.watchLoop()
	return j.logCh, nil
}

// Stop stops the journald watcher.
func (j *journaldWatcher) Stop() {
	j.tomb.Stop()
	if j.cancel != nil {
		j.cancel()
	}
	if j.cmd != nil && j.cmd.Process != nil {
		if err := util.Kill(j.cmd); err != nil {
			klog.Errorf("Failed to kill journalctl process: %v", err)
		}
	}
}

// watchLoop is the main watch loop of journald watcher.
func (j *journaldWatcher) watchLoop() {
	defer j.tomb.Done()

	stdout, err := j.cmd.StdoutPipe()
	if err != nil {
		klog.Errorf("Failed to get stdout pipe: %v", err)
		return
	}

	if err := j.cmd.Start(); err != nil {
		klog.Errorf("Failed to start journalctl command: %v", err)
		return
	}

	scanner := bufio.NewScanner(stdout)
	for {
		select {
		case <-j.tomb.Stopping():
			klog.Infof("Stop watching journald")
			return
		default:
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				klog.Errorf("Error reading journalctl output: %v", err)
			}
			return
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		entry, err := j.parseJournalEntry(line)
		if err != nil {
			klog.V(5).Infof("Failed to parse journal entry: %v", err)
			continue
		}

		if entry == nil {
			continue
		}

		j.logCh <- entry
	}
}

const (
	// configSourceKey is the key of source configuration in the plugin configuration.
	configSourceKey = "source"
)

// createJournalctlCommand creates the journalctl command with appropriate parameters.
func (j *journaldWatcher) createJournalctlCommand() (*exec.Cmd, error) {
	// Check if journalctl is available
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("journalctl binary not found: %v. This system does not appear to support systemd journald", err)
	}

	// Empty source is not allowed and treated as an error.
	source := j.cfg.PluginConfig[configSourceKey]
	if source == "" {
		return nil, fmt.Errorf("failed to filter journal log, empty source is not allowed")
	}

	args := []string{
		"--output=json", // Output in JSON format
		"--follow",      // Follow new entries
		"--no-pager",    // Don't use pager
		"--no-hostname", // Don't show hostname
		fmt.Sprintf("SYSLOG_IDENTIFIER=%s", source), // Filter by source
	}

	// Add log path if specified
	if j.cfg.LogPath != "" {
		// Check if the path exists
		if _, err := os.Stat(j.cfg.LogPath); err != nil {
			return nil, fmt.Errorf("failed to stat the log path %q: %v", j.cfg.LogPath, err)
		}
		args = append(args, fmt.Sprintf("--directory=%s", j.cfg.LogPath))
		klog.Infof("Using journal directory: %s", j.cfg.LogPath)
	} else {
		klog.Info("unspecified log path so using systemd default")
	}

	// Add since parameter based on start time
	seekTime := j.startTime
	now := time.Now()
	if now.Before(seekTime) {
		seekTime = now
	}
	args = append(args, fmt.Sprintf("--since=%s", seekTime.Format("2006-01-02 15:04:05")))

	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel

	cmd := exec.CommandContext(ctx, "journalctl", args...)

	return cmd, nil
}

// parseJournalEntry parses a JSON line from journalctl output into a Log entry.
func (j *journaldWatcher) parseJournalEntry(line string) (*logtypes.Log, error) {
	var entry JournalEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal journal entry: %v", err)
	}

	// Parse timestamp
	var timestamp time.Time
	if entry.Timestamp != "" {
		// Timestamp is in microseconds since epoch
		if ts, err := strconv.ParseInt(entry.Timestamp, 10, 64); err == nil {
			timestamp = time.Unix(0, ts*1000) // Convert microseconds to nanoseconds
		}
	}
	if timestamp.IsZero() && entry.SourceRealtimeTimestamp != "" {
		// Fallback to source timestamp
		if ts, err := strconv.ParseInt(entry.SourceRealtimeTimestamp, 10, 64); err == nil {
			timestamp = time.Unix(0, ts*1000)
		}
	}
	if timestamp.IsZero() {
		timestamp = time.Now() // Fallback to current time
	}

	// Check if this entry is before our start time
	if timestamp.Before(j.startTime) {
		klog.V(5).Infof("Throwing away journal entry %q before start time: %v < %v",
			entry.Message, timestamp, j.startTime)
		return nil, nil
	}

	message := strings.TrimSpace(entry.Message)
	return &logtypes.Log{
		Timestamp: timestamp,
		Message:   message,
	}, nil
}
