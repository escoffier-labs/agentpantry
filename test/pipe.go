package test

import "io"

// newPipe returns a synchronous in-memory pipe (reader, writer).
func newPipe() (*io.PipeReader, *io.PipeWriter) {
	return io.Pipe()
}
