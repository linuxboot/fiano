package fit

import (
	"fmt"
	"io"
)

var _ io.WriteSeeker = &writeSeekerWrapper{}

type writeSeekerWrapper struct {
	buffer []byte
	curPos uint
}

func newWriteSeekerWrapper(b []byte) *writeSeekerWrapper {
	return &writeSeekerWrapper{
		buffer: b,
	}
}

func (w *writeSeekerWrapper) Write(b []byte) (n int, err error) {
	endPos := w.curPos + uint(len(b))
	if len(b) > len(w.buffer)-int(w.curPos) {
		err = io.ErrShortWrite
	}
	copy(w.buffer[w.curPos:endPos], b)
	n = int(endPos) - int(w.curPos)
	w.curPos = endPos
	return
}

func (w *writeSeekerWrapper) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = int64(w.curPos) + offset
	case io.SeekEnd:
		newPos = int64(len(w.buffer)) + offset
	}

	if newPos < 0 {
		return int64(w.curPos), fmt.Errorf("requested position is negative: %d < 0", newPos)
	}
	if newPos > int64(len(w.buffer)) {
		return int64(w.curPos), fmt.Errorf("requested position is outside of the buffer: %d > %d", newPos, len(w.buffer))
	}

	w.curPos = uint(newPos)
	return int64(w.curPos), nil
}
