package bench

// ReadyFunc is called after a scenario binds its listener(s) but before any
// client traffic is initiated. It can be used to start external capture tools.
type ReadyFunc func(tcpPorts []uint16, udpPorts []uint16)
