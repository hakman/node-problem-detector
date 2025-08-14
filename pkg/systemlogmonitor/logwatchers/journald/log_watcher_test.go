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
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"k8s.io/node-problem-detector/pkg/systemlogmonitor/logwatchers/types"
	logtypes "k8s.io/node-problem-detector/pkg/systemlogmonitor/types"
)

func TestParseJournalEntry(t *testing.T) {
	watcher := &journaldWatcher{
		startTime: time.Unix(0, 0),
	}

	testCases := []struct {
		name     string
		jsonLine string
		expected *logtypes.Log
		hasError bool
	}{
		{
			name:     "valid entry with message",
			jsonLine: `{"MESSAGE":"log message","__REALTIME_TIMESTAMP":"123456789","SYSLOG_IDENTIFIER":"test-service"}`,
			expected: &logtypes.Log{
				Timestamp: time.Unix(0, 123456789*1000),
				Message:   "log message",
			},
			hasError: false,
		},
		{
			name:     "entry with source timestamp fallback",
			jsonLine: `{"MESSAGE":"another message","_SOURCE_REALTIME_TIMESTAMP":"987654321","SYSLOG_IDENTIFIER":"test-service"}`,
			expected: &logtypes.Log{
				Timestamp: time.Unix(0, 987654321*1000),
				Message:   "another message",
			},
			hasError: false,
		},
		{
			name:     "entry with empty message",
			jsonLine: `{"MESSAGE":"","__REALTIME_TIMESTAMP":"123456789","SYSLOG_IDENTIFIER":"test-service"}`,
			expected: &logtypes.Log{
				Timestamp: time.Unix(0, 123456789*1000),
				Message:   "",
			},
			hasError: false,
		},
		{
			name:     "invalid JSON",
			jsonLine: `{"MESSAGE":"log message","__REALTIME_TIMESTAMP":invalid}`,
			expected: nil,
			hasError: true,
		},
		{
			name:     "entry before start time",
			jsonLine: `{"MESSAGE":"old message","__REALTIME_TIMESTAMP":"0","SYSLOG_IDENTIFIER":"test-service"}`,
			expected: nil,
			hasError: false,
		},
	}

	// Set a start time that's after timestamp 0 for the last test case
	watcher.startTime = time.Unix(1, 0)

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			result, err := watcher.parseJournalEntry(test.jsonLine)

			if test.hasError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if test.expected == nil {
					assert.Nil(t, result)
				} else {
					assert.NotNil(t, result)
					assert.Equal(t, test.expected.Message, result.Message)
					assert.Equal(t, test.expected.Timestamp, result.Timestamp)
				}
			}
		})
	}
}

func TestCreateJournalctlCommand(t *testing.T) {
	testCases := []struct {
		name        string
		cfg         types.WatcherConfig
		expectError bool
	}{
		{
			name: "config without source",
			cfg: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{},
				LogPath:      "",
			},
			expectError: true,
		},
		{
			name: "config with non-existent log path",
			cfg: types.WatcherConfig{
				Plugin:       "journald",
				PluginConfig: map[string]string{"source": "test-service"},
				LogPath:      "/not/exist/path",
			},
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			watcher := &journaldWatcher{
				cfg:       test.cfg,
				startTime: time.Now(),
			}
			cmd, err := watcher.createJournalctlCommand()
			// Always expect error since we either have invalid config or journalctl is not available
			assert.Error(t, err)
			assert.Nil(t, cmd)
		})
	}
}

func TestGoroutineLeak(t *testing.T) {
	original := runtime.NumGoroutine()
	w := NewJournaldWatcher(types.WatcherConfig{
		Plugin:       "journald",
		PluginConfig: map[string]string{"source": "not-exist-service"},
		LogPath:      "/not/exist/path",
		Lookback:     "10m",
	})
	_, err := w.Watch()
	assert.Error(t, err)
	assert.Equal(t, original, runtime.NumGoroutine())
}
