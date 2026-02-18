package output

import "testing"

func TestNewFormatter(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"text", false},
		{"json", false},
		{"sarif", false},
		{"bogus", true},
	}
	for _, tt := range tests {
		_, err := NewFormatter(tt.name, false, false)
		if (err != nil) != tt.wantErr {
			t.Errorf("NewFormatter(%q) error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}
