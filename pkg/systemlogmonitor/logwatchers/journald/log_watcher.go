//go:build journald
// +build journald

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
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"k8s.io/node-problem-detector/pkg/systemlogmonitor/logwatchers/types"
	logtypes "k8s.io/node-problem-detector/pkg/systemlogmonitor/types"
	"k8s.io/node-problem-detector/pkg/util"
	"k8s.io/node-problem-detector/pkg/util/tomb"
)

const (
	// configSourceKey is the key of source configuration in the plugin configuration.
	configSourceKey = "source"
	// journalctlBinary is the path to the journalctl binary.
	journalctlBinary = "/usr/bin/journalctl"
	// maxRetries is the maximum number of retries for journalctl restart.
	maxRetries = 5
	// retryBackoffBase is the base duration for exponential backoff between retries.
	retryBackoffBase = time.Second
	// maxRetryBackoff is the maximum backoff duration between retries.
	maxRetryBackoff = 30 * time.Second
	// readTimeout is the timeout for reading from journalctl output.
	readTimeout = 10 * time.Second
	// logChannelBuffer is the buffer size for the log channel.
	logChannelBuffer = 1000
)

// journalEntry represents a single journal entry from journalctl JSON output.
type journalEntry struct {
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	Message           string `json:"MESSAGE"`
	SyslogIdentifier  string `json:"SYSLOG_IDENTIFIER"`
	Unit              string `json:"_SYSTEMD_UNIT"`
}

// journaldWatcher is the log watcher for journald using journalctl binary.
type journaldWatcher struct {
	cfg        types.WatcherConfig
	startTime  time.Time
	logCh      chan *logtypes.Log
	tomb       *tomb.Tomb
	cmd        *exec.Cmd
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	retryCount int
}

// NewJournaldWatcher creates a new journald watcher that uses journalctl binary.
func NewJournaldWatcher(cfg types.WatcherConfig) types.LogWatcher {
	uptime, err := util.GetUptimeDuration()
	if err != nil {
		klog.Fatalf("failed to get uptime: %v", err)
	}
	startTime, err := util.GetStartTime(time.Now(), uptime, cfg.Lookback, cfg.Delay)
	if err != nil {
		klog.Fatalf("failed to get start time: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &journaldWatcher{
		cfg:       cfg,
		startTime: startTime,
		tomb:      tomb.NewTomb(),
		logCh:     make(chan *logtypes.Log, logChannelBuffer),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Make sure NewJournaldWatcher is types.WatcherCreateFunc.
var _ types.WatcherCreateFunc = NewJournaldWatcher

// Watch starts the journal watcher.
func (j *journaldWatcher) Watch() (<-chan *logtypes.Log, error) {
	// Validate configuration
	if err := j.validateConfig(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Check if journalctl binary exists
	if err := j.checkJournalctlBinary(); err != nil {
		return nil, fmt.Errorf("journalctl binary check failed: %w", err)
	}

	// Start the watch loop
	go j.watchLoop()
	return j.logCh, nil
}

// Stop stops the journald watcher.
func (j *journaldWatcher) Stop() {
	j.tomb.Stop()
	j.cancel()

	j.mu.Lock()
	if j.cmd != nil && j.cmd.Process != nil {
		if err := util.Kill(j.cmd); err != nil {
			klog.Errorf("Failed to kill journalctl process: %v", err)
		}
	}
	j.mu.Unlock()
}

// validateConfig validates the watcher configuration.
func (j *journaldWatcher) validateConfig() error {
	source := j.cfg.PluginConfig[configSourceKey]
	if source == "" {
		return fmt.Errorf("empty source is not allowed")
	}

	if j.cfg.LogPath != "" {
		if _, err := os.Stat(j.cfg.LogPath); err != nil {
			return fmt.Errorf("failed to stat log path %q: %w", j.cfg.LogPath, err)
		}
	}

	return nil
}

// checkJournalctlBinary checks if journalctl binary exists and is executable.
func (j *journaldWatcher) checkJournalctlBinary() error {
	if _, err := os.Stat(journalctlBinary); err != nil {
		return fmt.Errorf("journalctl binary not found at %s: %w", journalctlBinary, err)
	}

	// Test if journalctl is executable by running a simple command
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, journalctlBinary, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("journalctl binary is not executable or systemd is not available: %w", err)
	}

	return nil
}

// watchLoop is the main watch loop of journald watcher.
func (j *journaldWatcher) watchLoop() {
	defer func() {
		close(j.logCh)
		j.tomb.Done()
	}()

	for {
		select {
		case <-j.tomb.Stopping():
			klog.Infof("Stop watching journald")
			return
		case <-j.ctx.Done():
			klog.Infof("Context cancelled, stopping journald watcher")
			return
		default:
		}

		if err := j.runJournalctl(); err != nil {
			select {
			case <-j.tomb.Stopping():
				// We're shutting down
				return
			default:
			}

			j.retryCount++
			if j.retryCount > maxRetries {
				klog.Errorf("Maximum retry attempts (%d) exceeded, stopping journald watcher: %v", maxRetries, err)
				return
			}

			backoff := j.calculateBackoff()
			klog.Errorf("journalctl failed (attempt %d/%d), retrying in %v: %v", j.retryCount, maxRetries, backoff, err)

			select {
			case <-time.After(backoff):
				continue
			case <-j.tomb.Stopping():
				return
			case <-j.ctx.Done():
				return
			}
		}

		// Reset retry count on successful run
		j.retryCount = 0
	}
}

// calculateBackoff calculates exponential backoff with jitter.
func (j *journaldWatcher) calculateBackoff() time.Duration {
	backoff := time.Duration(1<<uint(j.retryCount-1)) * retryBackoffBase
	if backoff > maxRetryBackoff {
		backoff = maxRetryBackoff
	}
	// Add some jitter (±20%)
	jitter := time.Duration(float64(backoff) * 0.2)
	backoff += time.Duration((int64(time.Now().UnixNano()) % int64(jitter*2)) - int64(jitter))
	// Ensure backoff doesn't exceed maximum after jitter
	if backoff > maxRetryBackoff {
		backoff = maxRetryBackoff
	}
	return backoff
}

// buildJournalctlArgs builds the arguments for the journalctl command.
func (j *journaldWatcher) buildJournalctlArgs() []string {
	args := []string{
		"--follow",      // Follow the journal
		"--output=json", // Output in JSON format
		"--no-tail",     // Don't show only the last 10 lines
		"--show-cursor", // Show cursor information
	}

	// Add directory if specified
	if j.cfg.LogPath != "" {
		args = append(args, "--directory="+j.cfg.LogPath)
	}

	// Add since timestamp
	since := j.startTime.Format("2006-01-02 15:04:05")
	args = append(args, "--since="+since)

	// Add source filter
	source := j.cfg.PluginConfig[configSourceKey]
	args = append(args, "SYSLOG_IDENTIFIER="+source)

	return args
}

// runJournalctl runs the journalctl command and processes its output.
func (j *journaldWatcher) runJournalctl() error {
	args := j.buildJournalctlArgs()

	j.mu.Lock()
	j.cmd = util.Exec(journalctlBinary, args...)
	j.mu.Unlock()

	klog.V(2).Infof("Starting journalctl with args: %v", args)

	stdout, err := j.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := j.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := j.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start journalctl: %w", err)
	}

	// Start goroutine to monitor stderr
	go j.monitorStderr(stderr)

	// Process stdout
	if err := j.processOutput(stdout); err != nil {
		// Kill the process if it's still running
		j.mu.Lock()
		if j.cmd.Process != nil {
			util.Kill(j.cmd)
		}
		j.mu.Unlock()
		return fmt.Errorf("failed to process journalctl output: %w", err)
	}

	// Wait for the command to finish
	if err := j.cmd.Wait(); err != nil {
		// Check if this is due to our intentional termination
		if strings.Contains(err.Error(), "killed") || strings.Contains(err.Error(), "signal") {
			klog.V(2).Infof("journalctl process terminated as expected")
			return nil
		}
		return fmt.Errorf("journalctl process exited with error: %w", err)
	}

	return nil
}

// monitorStderr monitors the stderr output of journalctl for errors.
func (j *journaldWatcher) monitorStderr(stderr io.ReadCloser) {
	defer stderr.Close()

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			klog.Warningf("journalctl stderr: %s", line)
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		klog.Errorf("Error reading journalctl stderr: %v", err)
	}
}

// processOutput processes the JSON output from journalctl.
func (j *journaldWatcher) processOutput(stdout io.ReadCloser) error {
	defer stdout.Close()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // Increase buffer size for large log entries

	for {
		select {
		case <-j.tomb.Stopping():
			return nil
		case <-j.ctx.Done():
			return nil
		default:
		}

		// Set read deadline to prevent indefinite blocking
		if deadlineErr := j.setReadDeadline(stdout); deadlineErr != nil {
			klog.V(4).Infof("Could not set read deadline: %v", deadlineErr)
		}

		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("scanner error: %w", err)
			}
			// EOF reached
			klog.V(2).Infof("journalctl output stream ended")
			return nil
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if err := j.processLogLine(line); err != nil {
			klog.Errorf("Failed to process log line: %v", err)
			continue
		}
	}
}

// setReadDeadline sets a read deadline on the reader if it supports it.
func (j *journaldWatcher) setReadDeadline(reader io.ReadCloser) error {
	if conn, ok := reader.(interface{ SetReadDeadline(time.Time) error }); ok {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	}
	return nil
}

// processLogLine processes a single JSON log line from journalctl.
func (j *journaldWatcher) processLogLine(line string) error {
	if line == "" {
		return nil
	}

	var entry journalEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return fmt.Errorf("failed to unmarshal journal entry: %w", err)
	}

	log := j.translateEntry(&entry)
	if log == nil {
		return nil // Skip this entry
	}

	// Non-blocking send to channel
	select {
	case j.logCh <- log:
	case <-j.tomb.Stopping():
		return nil
	case <-j.ctx.Done():
		return nil
	default:
		// Channel is full, drop the log entry and warn
		klog.Warningf("Log channel buffer full, dropping log entry: %s", log.Message)
	}

	return nil
}

// translateEntry translates a journal entry into internal log type.
func (j *journaldWatcher) translateEntry(entry *journalEntry) *logtypes.Log {
	// Parse timestamp
	timestampMicros, err := strconv.ParseUint(entry.RealtimeTimestamp, 10, 64)
	if err != nil {
		klog.Errorf("Failed to parse timestamp %q: %v", entry.RealtimeTimestamp, err)
		return nil
	}

	timestamp := time.Unix(0, int64(timestampMicros)*1000) // Convert microseconds to nanoseconds

	// Check if this entry is before our start time
	if timestamp.Before(j.startTime) {
		klog.V(5).Infof("Skipping journal entry before start time: %v < %v", timestamp, j.startTime)
		return nil
	}

	message := strings.TrimSpace(entry.Message)

	return &logtypes.Log{
		Timestamp: timestamp,
		Message:   message,
	}
}
