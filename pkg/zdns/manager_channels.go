package zdns

// ChannelManager defines the channels used to communicate outside the package
type ChannelManager struct {
	Add    chan Record
	Remove chan Record
	Update chan Record
	quit   chan bool
}

// NewChannelManager creates a new channel manager
func NewChannelManager() *ChannelManager {
	c := &ChannelManager{
		Add:    make(chan Record),
		Remove: make(chan Record),
		Update: make(chan Record),
		quit:   make(chan bool),
	}
	return c
}

// StartChannels starts the channel manager communications
func (m *Manager) StartChannels() {
	for {
		select {
		case <-m.Channels.quit:
			return
		case record := <-m.Channels.Add:
			dnscache.Add(record.Domain, record)
		case record := <-m.Channels.Remove:
			dnscache.Remove(record.Domain, record)
			//case record := <-c.Update:
		}
	}
}
