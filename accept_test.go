package tcpproxy

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// flakyListener returns each queued error from Accept, then blocks until it is
// closed, when it returns net.ErrClosed.
type flakyListener struct {
	mu     sync.Mutex
	errs   []error
	closed chan struct{}
	calls  int
}

func newFlakyListener(errs ...error) *flakyListener {
	return &flakyListener{errs: errs, closed: make(chan struct{})}
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *flakyListener) Close() error {
	close(l.closed)
	return nil
}

func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *flakyListener) acceptCalls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

func TestIsTransientAcceptError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"too many open files", &net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)}, true},
		{"file table full", fmt.Errorf("accept: %w", syscall.ENFILE), true},
		{"connection aborted", syscall.ECONNABORTED, true},
		{"timeout", &net.DNSError{IsTimeout: true}, true},
		{"closed listener", net.ErrClosed, false},
		{"closed listener wrapped", &net.OpError{Op: "accept", Err: net.ErrClosed}, false},
		{"unrecognised", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientAcceptError(tt.err); got != tt.want {
				t.Fatalf("isTransientAcceptError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestNextAcceptDelayGrowsAndIsCapped(t *testing.T) {
	d := time.Duration(0)
	var got []time.Duration
	for range 12 {
		d = nextAcceptDelay(d)
		got = append(got, d)
	}
	if got[0] != acceptRetryMin {
		t.Fatalf("first delay = %v, want %v", got[0], acceptRetryMin)
	}
	if got[1] != 2*acceptRetryMin {
		t.Fatalf("second delay = %v, want %v", got[1], 2*acceptRetryMin)
	}
	if last := got[len(got)-1]; last != acceptRetryMax {
		t.Fatalf("delay is not capped: %v, want %v", last, acceptRetryMax)
	}
}

func TestProxySurvivesTransientAcceptErrors(t *testing.T) {
	ln := newFlakyListener(syscall.EMFILE, syscall.EMFILE, syscall.ECONNABORTED)
	p := testProxy(t, ln)
	p.AddRoute(testFrontAddr, noopTarget{})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for ln.acceptCalls() < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("Accept called %d times, want it retried past the 3 errors", ln.acceptCalls())
		}
		time.Sleep(time.Millisecond)
	}

	waited := make(chan error, 1)
	go func() { waited <- p.Wait() }()
	select {
	case err := <-waited:
		t.Fatalf("Wait returned %v after transient errors; the listener should still be serving", err)
	case <-time.After(50 * time.Millisecond):
	}

	_ = p.Close()
	select {
	case err := <-waited:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Wait = %v, want net.ErrClosed once the listener is closed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Close")
	}
}

func TestProxyEndsOnPermanentAcceptError(t *testing.T) {
	boom := errors.New("listener broke")
	ln := newFlakyListener(boom)
	p := testProxy(t, ln)
	p.AddRoute(testFrontAddr, noopTarget{})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	waited := make(chan error, 1)
	go func() { waited <- p.Wait() }()
	select {
	case err := <-waited:
		if !errors.Is(err, boom) {
			t.Fatalf("Wait = %v, want %v", err, boom)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return for a permanent Accept error")
	}
}
