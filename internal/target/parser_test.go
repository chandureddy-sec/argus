package target

import (
	"testing"

	"reconx/pkg/models"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantType    models.TargetType
		wantValue   string
		expectError bool
	}{
		{
			name:      "Simple domain",
			input:     "example.com",
			wantType:  models.TargetTypeDomain,
			wantValue: "example.com",
		},
		{
			name:      "Subdomain",
			input:     "api.v1.example.com",
			wantType:  models.TargetTypeDomain,
			wantValue: "api.v1.example.com",
		},
		{
			name:      "Domain with URL scheme and path",
			input:     "https://sub.example.com:8443/login?redirect=1",
			wantType:  models.TargetTypeDomain,
			wantValue: "sub.example.com",
		},
		{
			name:      "IPv4 address",
			input:     "192.168.1.100",
			wantType:  models.TargetTypeIPv4,
			wantValue: "192.168.1.100",
		},
		{
			name:      "IPv4 with port",
			input:     "192.168.1.100:8080",
			wantType:  models.TargetTypeIPv4,
			wantValue: "192.168.1.100",
		},
		{
			name:      "IPv4 CIDR block",
			input:     "10.0.0.0/24",
			wantType:  models.TargetTypeCIDR,
			wantValue: "10.0.0.0/24",
		},
		{
			name:      "IPv6 address",
			input:     "2001:db8::1",
			wantType:  models.TargetTypeIPv6,
			wantValue: "2001:db8::1",
		},
		{
			name:      "IPv6 CIDR block",
			input:     "2001:db8::/32",
			wantType:  models.TargetTypeCIDR,
			wantValue: "2001:db8::/32",
		},
		{
			name:      "Explicit Org string",
			input:     "org:Tesla Inc",
			wantType:  models.TargetTypeOrg,
			wantValue: "Tesla Inc",
		},
		{
			name:      "Plain text organization name",
			input:     "Tesla Inc",
			wantType:  models.TargetTypeOrg,
			wantValue: "Tesla Inc",
		},
		{
			name:        "Empty target",
			input:       "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if got.Type != tt.wantType {
				t.Errorf("got Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Value != tt.wantValue {
				t.Errorf("got Value = %q, want %q", got.Value, tt.wantValue)
			}
		})
	}
}
