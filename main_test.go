package main

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"google.com", "google.com"},
		{"http://google.com", "google.com"},
		{"https://google.com", "google.com"},
		{"https://google.com/path", "google.com"},
		{"127.0.0.1", "127.0.0.1"},
		{"http://127.0.0.1:8080/", "127.0.0.1:8080"},
	}

	for _, tt := range tests {
		result := parseTarget(tt.input)
		if result != tt.expected {
			t.Errorf("parseTarget(%q) = %q; want %q", tt.input, result, tt.expected)
		}
	}
}
