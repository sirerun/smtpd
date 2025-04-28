package dmarc

import (
	"os"
	"testing"
	"time"
)

func TestDMARCEventAggregationAndReport(t *testing.T) {
	es := &DMARCEventStore{}
	// Add events
	es.AddEvent(DMARCEvent{
		Timestamp:   time.Now(),
		SourceIP:    "1.2.3.4",
		EnvelopeFrom: "sender@example.com",
		HeaderFrom:  "sender@example.com",
		PolicyDomain: "example.com",
		Disposition: "none",
		DKIMResult:  "pass",
		SPFResult:   "pass",
		Policy:      "none",
		SubdomainPolicy: "none",
		Reason:      "",
	})
	es.AddEvent(DMARCEvent{
		Timestamp:   time.Now(),
		SourceIP:    "1.2.3.4",
		EnvelopeFrom: "sender@example.com",
		HeaderFrom:  "sender@example.com",
		PolicyDomain: "example.com",
		Disposition: "none",
		DKIMResult:  "fail",
		SPFResult:   "pass",
		Policy:      "none",
		SubdomainPolicy: "none",
		Reason:      "",
	})
	// Generate report
	file, err := es.AggregateAndGenerateReport(os.TempDir(), "testorg", "test@example.com", time.Now().Add(-1*time.Hour).Unix(), time.Now().Unix())
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}
	if file == "" {
		t.Fatalf("Expected report file, got empty string")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("Failed to read report: %v", err)
	}
	if len(b) == 0 {
		t.Errorf("Report file is empty")
	}
	_ = os.Remove(file)
}

func TestParseRUA(t *testing.T) {
	record := "v=DMARC1; p=none; rua=mailto:agg1@example.com,mailto:agg2@example.com"
	addrs := ParseRUA(record)
	if len(addrs) != 2 {
		t.Fatalf("Expected 2 RUA addresses, got %d", len(addrs))
	}
	if addrs[0] != "mailto:agg1@example.com" || addrs[1] != "mailto:agg2@example.com" {
		t.Errorf("Unexpected RUA addresses: %v", addrs)
	}
}
