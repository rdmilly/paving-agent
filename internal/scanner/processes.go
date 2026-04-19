package scanner

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CollectProcesses captures every running process and returns both the
// flat list and a derived parent→children tree. We use `ps -eo` with a
// fixed column spec so our parser doesn't depend on any ps alias config.
//
// Memory is reported in RSS (kB) which is the actual resident size, not
// virtual — closer to what people mean when they ask "how much RAM is it
// using".
func CollectProcesses(ctx context.Context) ([]Process, []ProcessRelation, []string) {
	if !binaryExists("ps") {
		return nil, nil, []string{"processes: ps binary not found"}
	}

	out, err := runCmd(ctx, "ps", "-eo", "pid=,ppid=,user=,rss=,args=")
	if err != nil {
		return nil, nil, []string{fmt.Sprintf("processes: %v", err)}
	}

	var procs []Process
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		p, ok := parsePsLine(line)
		if ok {
			procs = append(procs, p)
		}
	}

	return procs, deriveProcessTree(procs), nil
}

// parsePsLine handles the 5-column ps output we asked for. ps right-pads
// numeric columns for alignment, so we use strings.Fields to tokenize the
// header and scan character-by-character for where the 4th field ends so
// we can preserve the full command with its internal spacing.
func parsePsLine(line string) (Process, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Process{}, false
	}

	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return Process{}, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return Process{}, false
	}
	user := fields[2]
	rss, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return Process{}, false
	}

	// Recover the full command string by skipping past the 4th whitespace-
	// separated field in the original line. Preserves any embedded spacing.
	cmd := afterNthField(line, 4)

	return Process{
		PID:      pid,
		PPID:     ppid,
		User:     user,
		MemoryKB: rss,
		Command:  cmd,
	}, true
}

// afterNthField returns the substring after the Nth whitespace-delimited
// field in s. Used to preserve the unmangled command string.
func afterNthField(s string, n int) string {
	s = strings.TrimLeft(s, " \t")
	count := 0
	inSpace := false
	for i, r := range s {
		if r == ' ' || r == '\t' {
			if !inSpace {
				count++
				if count == n {
					return strings.TrimLeft(s[i:], " \t")
				}
			}
			inSpace = true
		} else {
			inSpace = false
		}
	}
	return ""
}

// deriveProcessTree walks the flat process list and groups children by
// parent PID. Output is sorted by parent PID for stable diffing across
// scans. A process whose PPID doesn't appear in the list (e.g., the
// kernel's PID 2 on init systems we can't see into) is simply skipped
// as a parent key — its children still appear under their real parent
// if present.
func deriveProcessTree(procs []Process) []ProcessRelation {
	children := map[int][]int{}
	for _, p := range procs {
		children[p.PPID] = append(children[p.PPID], p.PID)
	}

	relations := make([]ProcessRelation, 0, len(children))
	for ppid, kids := range children {
		sort.Ints(kids)
		relations = append(relations, ProcessRelation{
			ParentPID: ppid,
			ChildPIDs: kids,
		})
	}
	sort.Slice(relations, func(i, j int) bool {
		return relations[i].ParentPID < relations[j].ParentPID
	})
	return relations
}
