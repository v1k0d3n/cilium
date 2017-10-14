package proto

import (
	"runtime/debug"
)

const (
	maxParseBufSize = 1024 * 1024 * 8
)

func allocParseBuf(size int) []byte {
	if size > maxParseBufSize {
		debug.PrintStack()
		size = maxParseBufSize
	}

	return make([]byte, size)
}
