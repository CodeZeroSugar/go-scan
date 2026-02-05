package icmpscanner

func incrementIP(current []byte) bool {
	if len(current) != 4 {
		return false
	}

	for i := 3; i >= 0; i-- {
		if current[i] < 255 {
			current[i]++
			return true
		}
		current[i] = 0
	}
	return false
}
