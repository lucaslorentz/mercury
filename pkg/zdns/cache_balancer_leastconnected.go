package zdns

// LeastConnected based loadbalancing interface for statistics
type LeastConnected struct{ Records }

// Less implements LeastConnected based loadbalancing by sorting based on leastconnected counter
func (s LeastConnected) Less(i, j int) bool {
	// Fallback to round robin if we have no connected values yet

	if s.Records[i].Statistics.Connected == 0 {
		return s.Records[i].Statistics.Requests < s.Records[j].Statistics.Requests

	}

	return s.Records[i].Statistics.Connected < s.Records[j].Statistics.Connected
}
