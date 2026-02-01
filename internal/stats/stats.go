package stats

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/CodeZeroSugar/go-scan/internal/paths"
)

type Stats struct {
	Ports map[int]PortStats `json:"ports"`
}

type PortStats struct {
	Count int `json:"count"`
}

func UpdateStats(ports []int) error {
	statPath, err := paths.StatsPath()
	if err != nil {
		return fmt.Errorf("failed to get path to stats", err)
	}
	jsonData, err := os.ReadFile(statPath)
	if err != nil {
		return fmt.Errorf("failed to read stats file", err)
	}

	var stats Stats
	err = json.Unmarshal(jsonData, &stats)
	if err != nil {
		return fmt.Errorf("failed to marshal stats json", err)
	}

	for _, p := range ports {
		if ps, exists := stats.Ports[p]; exists {
			ps.Count++
		} else {
			ps = PortStats{}
			stats.Ports[p] = ps
		}
	}

	json.Marshal(v any)
}
