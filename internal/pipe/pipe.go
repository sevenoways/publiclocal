// Package pipe copies bytes between two connections.
package pipe

import "io"

// Join copies in both directions until both sides are done, half-closing each
// destination when its source hits EOF, then closes both.
func Join(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	cp := func(dst, src io.ReadWriteCloser) {
		io.Copy(dst, src)
		closeWrite(dst)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// closeWrite half-closes c when it supports that (TCP, TLS). For a yamux
// stream, Close already is a half-close: it sends FIN but keeps reading.
func closeWrite(c io.Closer) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
