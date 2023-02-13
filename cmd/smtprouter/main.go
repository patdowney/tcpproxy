package main

import (
	"context"
	"fmt"

	"github.com/patdowney/tcpproxy"
)

func pretendMatcher(ctx context.Context, hostname string) (tcpproxy.Target, bool) {
	fmt.Printf("matched: %v\n", hostname)
	return tcpproxy.To("127.0.0.1:4567"), true
}

func main() {
	t := tcpproxy.Proxy{}

	t.AddSMTPSNIRouteFunc(":25", "mx.traffic.lab.dioad.net", pretendMatcher)

	err := t.Run()
	if err != nil {
		fmt.Printf("%v", err)
	}
}
