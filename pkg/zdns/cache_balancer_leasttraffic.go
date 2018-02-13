package zdns

// LeastTraffic based loadbalancing
type LeastTraffic struct{ Records }

// Less implements LeastTraffic based loadbalancing by sorting based on leasttraffic counter
func (s LeastTraffic) Less(i, j int) bool {
	// Fallback to round robin if we have no RX/TX values yet
	if s.Records[i].Statistics.RX+s.Records[i].Statistics.TX == 0 {
		return s.Records[i].Statistics.Requests < s.Records[j].Statistics.Requests

	}
	return s.Records[i].Statistics.RX+s.Records[i].Statistics.TX < s.Records[j].Statistics.RX+s.Records[j].Statistics.TX
}
