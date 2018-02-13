package zdns

import "fmt"

func (m *Manager) log(message string, args ...interface{}) {
	select {
	case m.Log <- fmt.Sprintf(message, args...):
	default:
	}
}
