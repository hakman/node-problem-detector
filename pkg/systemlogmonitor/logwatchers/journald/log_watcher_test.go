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
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"k8s.io/node-problem-detector/pkg/systemlogmonitor/logwatchers/types"
	logtypes "k8s.io/node-problem-detector/pkg/systemlogmonitor/types"
	"k8s.io/node-problem-detector/pkg/util/tomb"
)

func TestTranslateEntry(t *testing.T) {
	j := &journaldWatcher{
		startTime: time.Unix(0, 2000*1000), // 2000 microseconds = 2000000 nanoseconds
	}

	testCases := []struct {
		name     string
		entry    *journalEntry
		expected *logtypes.Log
	}{
		{
			name: "valid log entry with message",
			entry: &journalEntry{
				RealtimeTimestamp: "123456789",
				Message:           "log message",
				SyslogIdentifier:  "test-service",
			},
			expected: &logtypes.Log{
				Timestamp: time.Unix(0, 123456789*1000),
				Message:   "log message",
			},
		},
		{
			name: "entry with empty message",
			entry: &journalEntry{
				RealtimeTimestamp: "987654321",
				Message:           "",
				SyslogIdentifier:  "test-service",
			},
			expected: &logtypes.Log{
				Timestamp: time.Unix(0, 987654321*1000),
				Message:   "",
			},
		},
		{
			name: "entry with whitespace message",
			entry: &journalEntry{
				RealtimeTimestamp: "555555555",
				Message:           "  \t\n  ",
				SyslogIdentifier:  "test-service",
			},
			expected: &logtypes.Log{
				Timestamp: time.Unix(0, 555555555*1000),
				Message:   "",
			},
		},
		{
			name: "entry before start time",
			entry: &journalEntry{
				RealtimeTimestamp: "1000", // Very early timestamp
				Message:           "old message",
				SyslogIdentifier:  "test-service",
			},
			expected: nil, // Should be filtered out
		},
		{
			name: "invalid timestamp",
			entry: &journalEntry{
				RealtimeTimestamp: "invalid",
				Message:           "message",
				SyslogIdentifier:  "test-service",
			},
			expected: nil, // Should return nil for invalid timestamp
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := j.translateEntry(tc.entry)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateConfig(t *testing.T) {
	testCases := []struct {
		name      string
		config    types.WatcherConfig
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid config with source",
			config: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{"source": "test-service"},
				LogPath:      "", // Use default
				Lookback:     "10m",
			},
			expectErr: false,
		},
		{
			name: "missing source",
			config: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{},
				LogPath:      "",
				Lookback:     "10m",
			},
			expectErr: true,
			errMsg:    "empty source is not allowed",
		},
		{
			name: "empty source",
			config: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{"source": ""},
				LogPath:      "",
				Lookback:     "10m",
			},
			expectErr: true,
			errMsg:    "empty source is not allowed",
		},
		{
			name: "invalid log path",
			config: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{"source": "test-service"},
				LogPath:      "/nonexistent/path",
				Lookback:     "10m",
			},
			expectErr: true,
			errMsg:    "failed to stat log path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			j := &journaldWatcher{cfg: tc.config}
			err := j.validateConfig()

			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildJournalctlArgs(t *testing.T) {
	startTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	testCases := []struct {
		name     string
		config   types.WatcherConfig
		expected []string
	}{
		{
			name: "basic config",
			config: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{"source": "test-service"},
				LogPath:      "",
			},
			expected: []string{
				"--follow",
				"--output=json",
				"--no-tail",
				"--show-cursor",
				"--since=2023-01-01 12:00:00",
				"SYSLOG_IDENTIFIER=test-service",
			},
		},
		{
			name: "config with log path",
			config: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{"source": "my-service"},
				LogPath:      "/var/log/journal",
			},
			expected: []string{
				"--follow",
				"--output=json",
				"--no-tail",
				"--show-cursor",
				"--directory=/var/log/journal",
				"--since=2023-01-01 12:00:00",
				"SYSLOG_IDENTIFIER=my-service",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			j := &journaldWatcher{
				cfg:       tc.config,
				startTime: startTime,
			}
			result := j.buildJournalctlArgs()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCalculateBackoff(t *testing.T) {
	j := &journaldWatcher{}

	testCases := []struct {
		name       string
		retryCount int
		minBackoff time.Duration
		maxBackoff time.Duration
	}{
		{
			name:       "first retry",
			retryCount: 1,
			minBackoff: 800 * time.Millisecond,  // 1s - 20% jitter
			maxBackoff: 1200 * time.Millisecond, // 1s + 20% jitter
		},
		{
			name:       "second retry",
			retryCount: 2,
			minBackoff: 1600 * time.Millisecond, // 2s - 20% jitter
			maxBackoff: 2400 * time.Millisecond, // 2s + 20% jitter
		},
		{
			name:       "max backoff reached",
			retryCount: 10,
			minBackoff: 24 * time.Second, // 30s - 20% jitter
			maxBackoff: 30 * time.Second, // maxRetryBackoff
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			j.retryCount = tc.retryCount
			backoff := j.calculateBackoff()

			assert.True(t, backoff >= tc.minBackoff, "backoff %v should be >= %v", backoff, tc.minBackoff)
			assert.True(t, backoff <= tc.maxBackoff, "backoff %v should be <= %v", backoff, tc.maxBackoff)
		})
	}
}

func TestGoroutineLeak(t *testing.T) {
	// Skip this test if journalctl is not available
	if _, err := os.Stat(journalctlBinary); err != nil {
		t.Skipf("journalctl binary not found at %s, skipping test", journalctlBinary)
	}

	original := runtime.NumGoroutine()

	// Test with invalid log path
	w := NewJournaldWatcher(types.WatcherConfig{
		Plugin:       "journald",
		PluginConfig: map[string]string{"source": "not-exist-service"},
		LogPath:      "/not/exist/path",
		Lookback:     "10m",
	})
	_, err := w.Watch()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat log path")

	// Give a moment for any goroutines to clean up
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	runtime.GC() // Force garbage collection

	final := runtime.NumGoroutine()
	assert.Equal(t, original, final, "Goroutine leak detected: started with %d, ended with %d", original, final)
}

func TestWatcherLifecycle(t *testing.T) {
	// Skip this test if journalctl is not available
	if _, err := os.Stat(journalctlBinary); err != nil {
		t.Skipf("journalctl binary not found at %s, skipping test", journalctlBinary)
	}

	w := NewJournaldWatcher(types.WatcherConfig{
		Plugin:       "journald",
		PluginConfig: map[string]string{"source": "systemd"}, // systemd should exist
		LogPath:      "",
		Lookback:     "1s", // Very short lookback
	})

	logCh, err := w.Watch()
	require.NoError(t, err)
	require.NotNil(t, logCh)

	// Let it run for a short time
	time.Sleep(500 * time.Millisecond)

	// Stop the watcher
	w.Stop()

	// Verify the channel is closed eventually
	select {
	case _, ok := <-logCh:
		if !ok {
			// Channel is closed, which is expected
			break
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Channel was not closed within timeout")
	}
}

func TestProcessLogLine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := &journaldWatcher{
		startTime: time.Unix(0, 2000*1000), // 2000 microseconds = 2000000 nanoseconds
		logCh:     make(chan *logtypes.Log, 10),
		tomb:      tomb.NewTomb(),
		ctx:       ctx,
		cancel:    cancel,
	}

	testCases := []struct {
		name      string
		line      string
		expectErr bool
		expectLog bool
	}{
		{
			name:      "valid JSON log line",
			line:      `{"__REALTIME_TIMESTAMP":"123456789","MESSAGE":"test message","SYSLOG_IDENTIFIER":"test"}`,
			expectErr: false,
			expectLog: true,
		},
		{
			name:      "invalid JSON",
			line:      `{invalid json}`,
			expectErr: true,
			expectLog: false,
		},
		{
			name:      "empty line",
			line:      "",
			expectErr: false,
			expectLog: false,
		},
		{
			name:      "log entry before start time",
			line:      `{"__REALTIME_TIMESTAMP":"1000","MESSAGE":"old message","SYSLOG_IDENTIFIER":"test"}`,
			expectErr: false,
			expectLog: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the channel
			for len(j.logCh) > 0 {
				<-j.logCh
			}

			err := j.processLogLine(tc.line)

			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			if tc.expectLog {
				assert.Equal(t, 1, len(j.logCh), "Expected one log entry")
			} else {
				assert.Equal(t, 0, len(j.logCh), "Expected no log entries")
			}
		})
	}
}

func TestCheckJournalctlBinary(t *testing.T) {
	j := &journaldWatcher{}

	err := j.checkJournalctlBinary()
	if _, statErr := os.Stat(journalctlBinary); statErr != nil {
		// journalctl doesn't exist, expect error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "journalctl binary not found")
	} else {
		// journalctl exists, should not error (assuming systemd is available)
		assert.NoError(t, err)
	}
}
