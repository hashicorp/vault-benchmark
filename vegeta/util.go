package vegeta

// Simple Golang GCM/LCM for multiple mounts
//
// Copied from https://github.com/TheAlgorithms/Go/blob/master/math/lcm/lcm.go
// and https://github.com/TheAlgorithms/Go/blob/master/math/gcd/gcditerative.go
//
// License: MIT
func gcd(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func lcm(a, b int) int {
	a_ := int64(a)
	b_ := int64(b)
	return int((a_ * b_) / gcd(a_, b_))
}
