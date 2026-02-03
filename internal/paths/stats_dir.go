package paths

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/CodeZeroSugar/go-scan/internal/stats"
)

func scanStatsDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(base, "go-scan", "stats"), nil
}

func validateStats() (string, error) {
	dir, err := scanStatsDir()
	if err != nil {
		return "", err
	}

	err = os.MkdirAll(dir, 0o755)
	if err != nil {
		return "", err
	}

	filePath := filepath.Join(dir, "stats.json")

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		emptyStat := stats.Stats{Ports: make(map[int]stats.PortStats)}
		data, err := json.MarshalIndent(emptyStat, "", "	")
		if err != nil {
			return "", err
		}
		err = os.WriteFile(filePath, data, 0o644)
		if err != nil {
			return "", err
		}
	}

	return dir, nil
}

func StatsPath() (string, error) {
	dir, err := validateStats()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "stats.json"), nil
}
