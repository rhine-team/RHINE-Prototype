package common

// Returned by ILSes during GetRoots
type MSRoots struct {
	MSLR *MultiSignedLogRoot
	MSMR *MultiSignedMapRoot
}