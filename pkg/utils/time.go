package utils

import _ "unsafe"

//go:linkname now time.now
func now() (sec int64, nsec int32, mono int64)

func GetDiffWallMono() uint {
	sec, nsec, mono := now()
	wall := (uint(sec) << 32) | uint(nsec)
	return wall - uint(mono)
}
