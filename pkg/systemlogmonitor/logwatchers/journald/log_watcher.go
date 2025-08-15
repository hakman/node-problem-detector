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

// Package journald provides a watcher that tails systemd-journald logs by
// invoking the journalctl binary. This avoids a hard dependency on libsystemd
// and works across a wider range of distributions.
package journald

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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

// journaldWatcher tails journald via `journalctl` with robust restarts.
type journaldWatcher struct {
	cfg       types.WatcherConfig
	startTime time.Time
	logCh     chan *logtypes.Log
	tomb      *tomb.Tomb

	cmd *exec.Cmd
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

// Make sure NewJournaldWatcher is types.WatcherCreateFunc.
var _ types.WatcherCreateFunc = NewJournaldWatcher

// Watch starts the journal watcher.
func (j *journaldWatcher) Watch() (<-chan *logtypes.Log, error) {
	// Validate config early and fail fast to avoid goroutine leaks.
	source := j.cfg.PluginConfig[configSourceKey]
	if source == "" {
		return nil, fmt.Errorf("failed to filter journal log, empty source is not allowed")
	}
	if j.cfg.LogPath != "" {
		if _, err := os.Stat(j.cfg.LogPath); err != nil {
			return nil, fmt.Errorf("failed to stat the log path %q: %v", j.cfg.LogPath, err)
		}
	}
	// Ensure journalctl is available. Let util.Exec still construct the command,
	// but we provide a clearer error if it's missing from PATH.
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("journalctl not found in PATH: %v", err)
	}

	go j.watchLoop()
	return j.logCh, nil
}

// Stop stops the journald watcher.
func (j *journaldWatcher) Stop() {
	j.tomb.Stop()
}

// configSourceKey is the key of source configuration in the plugin configuration.
const configSourceKey = "source"

// watchLoop is the main watch loop of journald watcher.
// It continuously follows journald using `journalctl -f -o json` and
// restarts the command with exponential backoff on failures.
func (j *journaldWatcher) watchLoop() {
	defer j.tomb.Done()

	// Backoff parameters.
	const (
		initialBackoff = 1 * time.Second
		maxBackoff     = 30 * time.Second
	)
	backoff := initialBackoff

	for {
		select {
		case <-j.tomb.Stopping():
			j.terminateCmd()
			klog.Infof("Stop watching journald")
			return
		default:
		}

		_, stdout, err := j.startJournalctl()
		if err != nil {
			klog.Errorf("Failed to start journalctl: %v", err)
			// Respect stop signal during backoff.
			if j.waitOrStop(backoff) {
				return
			}
			// Exponential backoff with cap.
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		// Reset backoff on successful start
		backoff = initialBackoff

		scanner := bufio.NewScanner(stdout)
		// Allow large log lines. 10 MiB cap.
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 10*1024*1024)

		readErr := j.scanLoop(scanner)

		// Ensure process is terminated and reaped.
		_ = stdout.Close()
		_ = j.terminateCmd()

		if readErr != nil && readErr != os.ErrClosed {
			klog.Errorf("journalctl stream error: %v", readErr)
		}

		// If stop requested, exit.
		select {
		case <-j.tomb.Stopping():
			klog.Infof("Stop watching journald")
			return
		default:
		}

		// Restart after backoff.
		if j.waitOrStop(backoff) {
			return
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// startJournalctl constructs and starts the journalctl command and returns its stdout pipe.
func (j *journaldWatcher) startJournalctl() (*exec.Cmd, io.ReadCloser, error) {
	args := j.buildJournalctlArgs()
	cmd := util.Exec("journalctl", args...)

	// Pipe stdout for incremental consumption.
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get journalctl stdout: %w", err)
	}
	// Print stderr to process stderr to aid debugging, but avoid blocking.
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		return nil, nil, fmt.Errorf("failed to start journalctl: %w", err)
	}
	j.cmd = cmd
	klog.Infof("Started journalctl with args: %v", args)
	return cmd, stdout, nil
}

// terminateCmd attempts to kill journalctl and wait for it to exit.
func (j *journaldWatcher) terminateCmd() error {
	if j.cmd == nil {
		return nil
	}
	// Send SIGKILL to the process group to ensure any children are also killed.
	_ = util.Kill(j.cmd)
	// Best effort wait to reap the process and avoid zombies.
	_ = j.cmd.Wait()
	j.cmd = nil
	return nil
}

// waitOrStop sleeps for d or returns true if stop signal is received during the wait.
func (j *journaldWatcher) waitOrStop(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-j.tomb.Stopping():
		return true
	case <-timer.C:
		return false
	}
}

// scanLoop reads newline-delimited JSON entries from scanner and forwards them as logs.
func (j *journaldWatcher) scanLoop(scanner *bufio.Scanner) error {
	for {
		select {
		case <-j.tomb.Stopping():
			return nil
		default:
		}

		if !scanner.Scan() {
			return scanner.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// journalctl -o json emits one JSON object per line.
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			// Malformed line; continue.
			klog.Errorf("Failed to parse journalctl JSON: %v; line=%q", err, string(line))
			continue
		}
		l := translateJSON(m)
		j.logCh <- l
	}
}

// buildJournalctlArgs returns the args for a long-running tail from startTime with filtering.
func (j *journaldWatcher) buildJournalctlArgs() []string {
	args := []string{
		"--follow",
		"--no-pager",
		"--output=json",
		"--quiet",
	}

	// Start time: use local time format accepted by systemd time parser.
	// Example: 2006-01-02 15:04:05
	seekTime := j.startTime
	now := time.Now()
	if now.Before(seekTime) {
		seekTime = now
	}
	args = append(args, "--since="+seekTime.Local().Format("2006-01-02 15:04:05"))

	// Restrict to a directory if provided.
	if j.cfg.LogPath != "" {
		args = append(args, "-D", j.cfg.LogPath)
	} else {
		klog.Info("unspecified log path so using systemd default")
	}

	// Filter by SYSLOG_IDENTIFIER to match previous behavior.
	source := j.cfg.PluginConfig[configSourceKey]
	// Positional match expression: FIELD=VALUE
	args = append(args, "SYSLOG_IDENTIFIER="+source)

	return args
}

// translateJSON translates a journalctl JSON line into internal type.
// It relies on MESSAGE and __REALTIME_TIMESTAMP (microseconds since epoch).
func translateJSON(entry map[string]any) *logtypes.Log {
	// MESSAGE
	var message string
	if v, ok := entry["MESSAGE"]; ok {
		if s, ok := v.(string); ok {
			message = strings.TrimSpace(s)
		}
	}

	// __REALTIME_TIMESTAMP (microseconds since epoch), commonly a string.
	var ts time.Time
	if v, ok := entry["__REALTIME_TIMESTAMP"]; ok {
		switch t := v.(type) {
		case string:
			if us, err := strconv.ParseInt(t, 10, 64); err == nil {
				ts = time.Unix(0, us*1000)
			}
		case float64:
			// Shouldn't happen often, but handle it.
			us := int64(t)
			ts = time.Unix(0, us*1000)
		}
	}
	// If missing or failed to parse, fallback to now to avoid blocking.
	if ts.IsZero() {
		ts = time.Now()
	}

	return &logtypes.Log{
		Timestamp: ts,
		Message:   message,
	}
}
