//go:build go1.8
// +build go1.8

package handlers

import (
	"fmt"

	"github.com/chenjz24/net/http"
)

type loggingResponseWriter interface {
	commonLoggingResponseWriter
	http.Pusher
}

func (l *responseLogger) Push(target string, opts *http.PushOptions) error {
	p, ok := l.w.(http.Pusher)
	if !ok {
		return fmt.Errorf("responseLogger does not implement http.Pusher")
	}
	return p.Push(target, opts)
}
