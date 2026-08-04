package core

import (
	"testing"
	"strings"
)

func assertRule(t *testing.T, expected, result *Rule, input string) {
	if result == nil && expected != nil {
		t.Errorf("Test failed [%s]:\nExpected -> %v\nActual -> nil (rule incorrectly dropped)", input, expected)
	} else if result != nil && expected == nil {
		t.Errorf("Test failed [%s]:\nExpected -> nil (rule should be dropped)\nActual -> %v", input, result)
	} else if result != nil && (result.Type != expected.Type || result.Value != expected.Value) {
		t.Errorf("Test failed [%s]:\nExpected -> Type: %s, Value: %s\nActual -> Type: %s, Value: %s",
			input, expected.Type, expected.Value, result.Type, result.Value)
	}
}

func TestParseV2Ray(t *testing.T) {
	tests := []struct {
		input    string
		expected *Rule
	}{
		{"full:google.com", &Rule{"DOMAIN", "google.com"}},
		{"domain:google.com", &Rule{"DOMAIN-SUFFIX", "google.com"}},
		{"keyword:google", &Rule{"DOMAIN-KEYWORD", "google"}},
		{"regexp:^.*google.*$", &Rule{"DOMAIN-REGEX", "^.*google.*$"}},
		{"regex:^.*google.*$", &Rule{"DOMAIN-REGEX", "^.*google.*$"}},
		{".google.com", &Rule{"DOMAIN-SUFFIX", "google.com"}},
		{"google.com", &Rule{"DOMAIN-KEYWORD", "google.com"}},
		{"google.com @ads", &Rule{"DOMAIN-KEYWORD", "google.com"}},
		{"192.168.1.1", &Rule{"IP-CIDR", "192.168.1.1/32"}},
		{"10.0.0.0/8", &Rule{"IP-CIDR", "10.0.0.0/8"}},
		{"2001:db8::/32", &Rule{"IP-CIDR6", "2001:db8::/32"}},
		{"include:other_file", nil},
		{"ext:other_file.dat", nil},
	}

	for _, tt := range tests {
		result := ParseV2Ray(tt.input)
		assertRule(t, tt.expected, result, tt.input)
	}
}

func TestParseClash(t *testing.T) {
	tests := []struct {
		input    string
		expected *Rule
	}{
		{"DOMAIN,google.com", &Rule{"DOMAIN", "google.com"}},
		{"DOMAIN-SUFFIX,google.com", &Rule{"DOMAIN-SUFFIX", "google.com"}},
		{"DOMAIN-KEYWORD,google", &Rule{"DOMAIN-KEYWORD", "google"}},
		{"IP-CIDR,192.168.0.0/16", &Rule{"IP-CIDR", "192.168.0.0/16"}},
		{"IP-CIDR6,2001:db8::/32", &Rule{"IP-CIDR6", "2001:db8::/32"}},
		{"IP-CIDR,10.0.0.0/8,no-resolve", &Rule{"IP-CIDR", "10.0.0.0/8"}},
		{"PROCESS-NAME,v2ray.exe", &Rule{"PROCESS-NAME", "v2ray.exe"}},
		{"PROCESS-PATH,/usr/bin/v2ray", &Rule{"PROCESS-PATH", "/usr/bin/v2ray"}},
		{"google.com", &Rule{"DOMAIN", "google.com"}},
		{"+.google.com", &Rule{"DOMAIN-SUFFIX", "google.com"}},
		{".google.com", &Rule{"DOMAIN-REGEX", "^.+\\.google\\.com$"}},
		{"*.google.com", &Rule{"DOMAIN-REGEX", "^[^.]+\\.google\\.com$"}},
		{"*", &Rule{"DOMAIN-REGEX", "^[^.]+$"}},
		{"- DOMAIN,apple.com", &Rule{"DOMAIN", "apple.com"}},
		{"- payload:", nil},
	}

	for _, tt := range tests {
		result := ParseClash(tt.input)
		assertRule(t, tt.expected, result, tt.input)
	}
}

func TestParseEgern(t *testing.T) {
	tests := []struct {
		input    string
		section  string
		expected *Rule
	}{
		{"google.com", "domain_set", &Rule{"DOMAIN", "google.com"}},
		{".google.com", "domain_suffix_set", &Rule{"DOMAIN-SUFFIX", "google.com"}},
		{"google.com", "domain_suffix_set", &Rule{"DOMAIN-SUFFIX", "google.com"}},
		{"google", "domain_keyword_set", &Rule{"DOMAIN-KEYWORD", "google"}},
		{"^.*google.*$", "domain_regex_set", &Rule{"DOMAIN-REGEX", "^.*google.*$"}},
		{"192.168.1.1", "ip_cidr_set", &Rule{"IP-CIDR", "192.168.1.1/32"}},
		{"10.0.0.0/8", "ip_cidr_set", &Rule{"IP-CIDR", "10.0.0.0/8"}},
		{"2001:db8::", "ip_cidr6_set", &Rule{"IP-CIDR6", "2001:db8::/128"}},
		{"12345", "asn_set", &Rule{"IP-ASN", "12345"}},
		{"v2ray*", "user_agent_set", &Rule{"PROCESS-NAME", "v2ray"}},
		{".example.com", "", &Rule{"DOMAIN-SUFFIX", "example.com"}},
		{"example.com", "", &Rule{"DOMAIN", "example.com"}},
		{"# comment", "domain_set", nil},
		{"// comment", "domain_set", nil},
	}

	for _, tt := range tests {
		result := ParseEgern(tt.input, tt.section)
		assertRule(t, tt.expected, result, tt.input+" (section: "+tt.section+")")
	}
}

func TestParseAdblockAndWhite(t *testing.T) {
	adblockTests := []struct {
		input    string
		expected *Rule
	}{
		{"||example.com^", &Rule{"DOMAIN-SUFFIX", "example.com"}},
		{"||*.example.com^", &Rule{"DOMAIN-REGEX", "^(.+\\.)?.*\\.example\\.com$"}},
		{"||example.com^$third-party", nil},
		{"||example.com/path", nil},
	}
	for _, tt := range adblockTests {
		result := ParseAdblock(tt.input)
		assertRule(t, tt.expected, result, tt.input)
	}

	whiteTests := []struct {
		input    string
		expected *Rule
	}{
		{"@@||example.com^", &Rule{"DOMAIN-SUFFIX", "example.com"}},
		{"@@|example.com^", &Rule{"DOMAIN", "example.com"}},
		{"@@||example.com^$important", nil},
		{"@@||*.example.com^", &Rule{"DOMAIN-REGEX", "^(.+\\.)?.*\\.example\\.com$"}},
	}
	for _, tt := range whiteTests {
		result := ParseWhite(tt.input)
		assertRule(t, tt.expected, result, tt.input)
	}
}

func TestParseDNSFormats(t *testing.T) {
	hostsResult := ParseHosts("127.0.0.1 google.com")
	assertRule(t, &Rule{"DOMAIN", "google.com"}, hostsResult, "127.0.0.1 google.com")

	hostsResultWildcard := ParseHosts("0.0.0.0 *.google.com")
	assertRule(t, &Rule{"DOMAIN-REGEX", "^[^.]+\\.google\\.com$"}, hostsResultWildcard, "0.0.0.0 *.google.com")

	dnsmasqResult := ParseDnsmasq("address=/google.com/0.0.0.0")
	assertRule(t, &Rule{"DOMAIN-SUFFIX", "google.com"}, dnsmasqResult, "address=/google.com/0.0.0.0")

	smartdnsResult := ParseSmartDNS("address /google.com/#")
	assertRule(t, &Rule{"DOMAIN-SUFFIX", "google.com"}, smartdnsResult, "address /google.com/#")
}


func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		errContains string
	}{
		{
			name: "Valid configuration",
			config: Config{
				Categories: []Category{
					{Name: "base", Upstreams: []Upstream{{URL: "http://a.com", Parser: "clash"}}},
					{Name: "extended", MergeFrom: []string{"base"}},
				},
			},
			expectError: false,
		},
		{
			name: "Duplicate category name",
			config: Config{
				Categories: []Category{ {Name: "proxy"}, {Name: "proxy"} },
			},
			expectError: true, errContains: "duplicate category name",
		},
		{
			name: "Invalid white behavior",
			config: Config{
				Categories: []Category{ {Name: "reject", WhiteBehavior: "magic_delete"} },
			},
			expectError: true, errContains: "white_behavior must be",
		},
		{
			name: "Merge from non-existent category",
			config: Config{
				Categories: []Category{
					{Name: "main_cat", MergeFrom: []string{"ghost_cat"}},
				},
			},
			expectError: true, errContains: "non-existent category",
		},
		{
			name: "Invalid parser",
			config: Config{
				Categories: []Category{
					{Name: "bad_parser", Upstreams: []Upstream{{URL: "http", Parser: "super_parser"}}},
				},
			},
			expectError: true, errContains: "invalid parser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected an error, but validation passed")
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error message mismatch:\nExpected to contain: %s\nActual: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected validation to pass, but got error: %v", err)
				}
			}
		})
	}
}