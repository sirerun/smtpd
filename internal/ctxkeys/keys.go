package ctxkeys

// contextKey is an unexported type to be used as key for context values.
// This prevents collisions with keys defined in other packages.
type contextKey string

const (
	// SPFResultKey is the context key for storing the SPF check result.
	// The associated value should be of type spf.Result (or similar defined type).
	SPFResultKey contextKey = "spfResult"

	// DKIMResultsKey is the context key for storing the results of DKIM verification.
	// The associated value should be a slice []*dkim.Verification or similar.
	DKIMResultsKey contextKey = "dkimResults"
)
