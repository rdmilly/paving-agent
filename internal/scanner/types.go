package scanner

// NodeScan is the full ground-truth state captured from a single node at a
// single point in time. It is the input to the NodeDefinition generator.
type NodeScan struct {
	SchemaVersion string `json:"schema_version"`
	CapturedAt    string `json:"captured_at"` // RFC3339 UTC
	DurationMS    int64  `json:"duration_ms"`

	Host        Host         `json:"host"`
	Ports       []Port       `json:"ports"`
	Processes   []Process    `json:"processes"`
	Containers  []Container  `json:"containers"`
	Services    []Service    `json:"services"`
	Connections []Connection `json:"connections"`
	Routes      []Route      `json:"routes"`

	// Warnings collects soft failures (missing binaries, permission issues)
	// that did not prevent a scan but left a section empty or partial.
	Warnings []string `json:"warnings"`
}

// Host captures identity and resource state of the node itself.
type Host struct {
	Hostname    string `json:"hostname"`
	Kernel      string `json:"kernel"`
	Distro      string `json:"distro"`
	Arch        string `json:"arch"`
	UptimeSec   int64  `json:"uptime_sec"`
	CPUCores    int    `json:"cpu_cores"`
	MemoryMB    int64  `json:"memory_mb"`
	DiskTotalGB int64  `json:"disk_total_gb"`
	DiskFreeGB  int64  `json:"disk_free_gb"`
}

// Port is a listening TCP socket and the process that owns it.
type Port struct {
	Addr    string `json:"addr"` // e.g., 0.0.0.0, 127.0.0.1, ::
	Port    int    `json:"port"`
	Proto   string `json:"proto"` // tcp, tcp6
	PID     int    `json:"pid"`
	Process string `json:"process"`
}

// Process is an OS process. We capture only top-level state; deep inspection
// is the job of sidecar probes, not the scanner.
type Process struct {
	PID      int    `json:"pid"`
	PPID     int    `json:"ppid"`
	User     string `json:"user"`
	Command  string `json:"command"`
	MemoryKB int64  `json:"memory_kb"`
}

// Container is a Docker container as reported by `docker ps`.
type Container struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	Status  string            `json:"status"`
	State   string            `json:"state"` // running, exited, etc.
	Ports   []string          `json:"ports"`
	Network string            `json:"network"`
	Labels  map[string]string `json:"labels"`
}

// Service is a systemd unit in the running or failed state.
type Service struct {
	Name       string `json:"name"`
	LoadState  string `json:"load_state"`
	ActiveState string `json:"active_state"`
	SubState   string `json:"sub_state"`
	Description string `json:"description"`
}

// Connection is an established outbound TCP connection. Used to build the
// ground-truth service graph: who actually talks to whom, not what
// configuration claims.
type Connection struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"` // ESTAB, TIME-WAIT, etc.
	PID        int    `json:"pid"`
	Process    string `json:"process"`
}

// Route is a row from `ip route`. We keep the default route specifically;
// the primary interface drives packet-trace selection.
type Route struct {
	Destination string `json:"destination"` // e.g., "default", "10.0.0.0/24"
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	IsDefault   bool   `json:"is_default"`
}
