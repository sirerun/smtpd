package dmarc

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DMARCEvent represents a single DMARC evaluation result for reporting.
type DMARCEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	EnvelopeFrom string   `json:"envelope_from"`
	HeaderFrom  string    `json:"header_from"`
	PolicyDomain string   `json:"policy_domain"`
	Disposition string    `json:"disposition"`
	DKIMResult  string    `json:"dkim_result"`
	SPFResult   string    `json:"spf_result"`
	Policy      string    `json:"policy"`
	SubdomainPolicy string `json:"subdomain_policy"`
	Reason      string    `json:"reason"`
}

// DMARCEventStore stores DMARC events for aggregation and reporting.
type DMARCEventStore struct {
	Events []DMARCEvent
	mu     sync.Mutex
}

// AddEvent appends a DMARC event to the store.
func (s *DMARCEventStore) AddEvent(e DMARCEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = append(s.Events, e)
}

// Clear removes all events from the store.
func (s *DMARCEventStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Events = nil
}

// DMARCReport represents an aggregate XML report per RFC 7489 (simplified)
type DMARCReport struct {
	XMLName         xml.Name         `xml:"feedback"`
	ReportMetadata  ReportMetadata   `xml:"report_metadata"`
	PolicyPublished PolicyPublished  `xml:"policy_published"`
	Records         []Record         `xml:"record"`
}

type ReportMetadata struct {
	OrgName   string    `xml:"org_name"`
	Email     string    `xml:"email"`
	ReportID  string    `xml:"report_id"`
	DateRange DateRange `xml:"date_range"`
}

type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

type PolicyPublished struct {
	Domain string `xml:"domain"`
	ADKIM  string `xml:"adkim"`
	ASPF   string `xml:"aspf"`
	P      string `xml:"p"`
	SP     string `xml:"sp"`
}

type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

type PolicyEvaluated struct {
	Disposition string `xml:"disposition"`
	DKIM        string `xml:"dkim"`
	SPF         string `xml:"spf"`
}

type Identifiers struct {
	EnvelopeFrom string `xml:"envelope_from"`
	HeaderFrom   string `xml:"header_from"`
}

type AuthResults struct {
	DKIM []DKIMAuthResult `xml:"dkim"`
	SPF  []SPFAuthResult  `xml:"spf"`
}

type DKIMAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

type SPFAuthResult struct {
	Domain string `xml:"domain"`
	Result string `xml:"result"`
}

// AggregateAndGenerateReport aggregates events and writes XML report to storagePath
func (s *DMARCEventStore) AggregateAndGenerateReport(storagePath, orgName, orgEmail string, begin, end int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Events) == 0 {
		return "", nil
	}
	// Group by PolicyDomain+SourceIP+Disposition
	type groupKey struct {
		Domain      string
		SourceIP    string
		Disposition string
	}
	groups := make(map[groupKey][]DMARCEvent)
	for _, e := range s.Events {
		k := groupKey{Domain: e.PolicyDomain, SourceIP: e.SourceIP, Disposition: e.Disposition}
		groups[k] = append(groups[k], e)
	}
	var records []Record
	for k, evs := range groups {
		records = append(records, Record{
			Row: Row{
				SourceIP: k.SourceIP,
				Count:    len(evs),
				PolicyEvaluated: PolicyEvaluated{
					Disposition: k.Disposition,
					DKIM:        evs[0].DKIMResult,
					SPF:         evs[0].SPFResult,
				},
			},
			Identifiers: Identifiers{
				EnvelopeFrom: evs[0].EnvelopeFrom,
				HeaderFrom:   evs[0].HeaderFrom,
			},
			AuthResults: AuthResults{
				DKIM: []DKIMAuthResult{{Domain: evs[0].PolicyDomain, Result: evs[0].DKIMResult}},
				SPF:  []SPFAuthResult{{Domain: evs[0].PolicyDomain, Result: evs[0].SPFResult}},
			},
		})
	}
	// Sort for stable output
	sort.Slice(records, func(i, j int) bool {
		if records[i].Row.SourceIP != records[j].Row.SourceIP {
			return records[i].Row.SourceIP < records[j].Row.SourceIP
		}
		return records[i].Identifiers.EnvelopeFrom < records[j].Identifiers.EnvelopeFrom
	})
	report := DMARCReport{
		ReportMetadata: ReportMetadata{
			OrgName:   orgName,
			Email:     orgEmail,
			ReportID:  fmt.Sprintf("%d-%s", begin, orgName),
			DateRange: DateRange{Begin: begin, End: end},
		},
		PolicyPublished: PolicyPublished{
			Domain: records[0].Identifiers.EnvelopeFrom,
			ADKIM:  "r",
			ASPF:   "r",
			P:      records[0].Row.PolicyEvaluated.Disposition,
			SP:     "none",
		},
		Records: records,
	}
	buf := &bytes.Buffer{}
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(buf)
	enc.Indent("", "  ")
	if err := enc.Encode(report); err != nil {
		return "", err
	}
	filename := fmt.Sprintf("%s/dmarc_report_%d.xml", storagePath, end)
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	return filename, nil
}

// ParseRUA parses rua addresses from a DMARC record string
func ParseRUA(record string) []string {
	var uris []string
	for _, part := range strings.Split(record, ";") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, "rua=") {
			addrs := strings.TrimPrefix(p, "rua=")
			for _, addr := range strings.Split(addrs, ",") {
				uri := strings.TrimSpace(addr)
				if uri != "" {
					uris = append(uris, uri)
				}
			}
		}
	}
	return uris
}

// SendAggregateReport sends the XML report to each RUA address via SMTP (mailto only)
func SendAggregateReport(reportPath string, rua []string, from string) error {
	// Implementation stub: just print what would be sent
	for _, uri := range rua {
		if strings.HasPrefix(uri, "mailto:") {
			addr := strings.TrimPrefix(uri, "mailto:")
			fmt.Printf("Would send DMARC report %s to %s\n", reportPath, addr)
		}
	}
	return nil
}
