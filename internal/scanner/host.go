package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// CollectHost gathers identity and resource state for the node. Reads from
// /proc and syscalls directly — no external binaries required, so this
// collector never fails soft. If we can't read /proc we can't run at all.
func CollectHost(ctx context.Context) (Host, []string) {
	var warnings []string
	h := Host{
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}

	if hn, err := os.Hostname(); err == nil {
		h.Hostname = hn
	} else {
		warnings = append(warnings, fmt.Sprintf("host: hostname: %v", err))
	}

	if out, err := runCmd(ctx, "uname", "-r"); err == nil {
		h.Kernel = strings.TrimSpace(string(out))
	} else {
		warnings = append(warnings, fmt.Sprintf("host: uname: %v", err))
	}

	h.Distro = readDistro(&warnings)
	h.UptimeSec = readUptime(&warnings)
	h.MemoryMB = readMemTotalMB(&warnings)
	h.DiskTotalGB, h.DiskFreeGB = readRootDiskGB(&warnings)

	return h, warnings
}

// readDistro parses /etc/os-release. Format is `KEY="value"` per line.
// We want PRETTY_NAME (e.g., "Ubuntu 24.04.1 LTS").
func readDistro(warnings *[]string) string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("host: os-release: %v", err))
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// readUptime reads /proc/uptime. First field is seconds since boot as a float.
func readUptime(warnings *[]string) int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("host: uptime: %v", err))
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

// readMemTotalMB pulls MemTotal from /proc/meminfo. Values are in kB.
func readMemTotalMB(warnings *[]string) int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("host: meminfo: %v", err))
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return kb / 1024
				}
			}
		}
	}
	return 0
}

// readRootDiskGB stats the root filesystem for total + free bytes.
func readRootDiskGB(warnings *[]string) (int64, int64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		*warnings = append(*warnings, fmt.Sprintf("host: statfs: %v", err))
		return 0, 0
	}
	total := int64(stat.Blocks) * int64(stat.Bsize) / (1024 * 1024 * 1024)
	free := int64(stat.Bavail) * int64(stat.Bsize) / (1024 * 1024 * 1024)
	return total, free
}
