package paths

import (
	"os"
	"path/filepath"
)

func scanStatsDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(base, "go-scan//stats"), nil
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
	return dir, nil
}

func StatsPath() (string, error) {
	dir, err := validateStats()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, "stats.json"), nil
}
