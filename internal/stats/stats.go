package stats

import (
	"encoding/json"
	"fmt"
	"os"
)

type Stats struct {
	Ports map[int]PortStats `json:"ports"`
}

type PortStats struct {
	Count int `json:"count"`
}

func RetrieveStats(statPath string) (*Stats, error) {
	jsonData, err := os.ReadFile(statPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read stats file: %w", err)
	}

	var stats Stats
	err = json.Unmarshal(jsonData, &stats)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal stats json: %w", err)
	}

	if stats.Ports == nil {
		return nil, fmt.Errorf("no stats available to report")
	}

	return &stats, nil
}

func UpdateStats(ports []int, statPath string) error {
	jsonData, err := os.ReadFile(statPath)
	if err != nil {
		return fmt.Errorf("failed to read stats file: %w", err)
	}

	var stats Stats
	err = json.Unmarshal(jsonData, &stats)
	if err != nil {
		return fmt.Errorf("failed to unmarshal stats json: %w", err)
	}

	if stats.Ports == nil {
		stats.Ports = make(map[int]PortStats)
	}

	for _, p := range ports {
		ps, exists := stats.Ports[p]
		if exists {
			ps.Count++
			stats.Ports[p] = ps
		} else {
			ps = PortStats{Count: 1}
			stats.Ports[p] = ps
		}
	}

	updatedData, err := json.MarshalIndent(stats, "", "	")
	if err != nil {
		return fmt.Errorf("failed to marshal updated json: %w", err)
	}

	if err := os.WriteFile(statPath, updatedData, 0o644); err != nil {
		return fmt.Errorf("failed to write updates to stats file: %w", err)
	}

	return nil
}
