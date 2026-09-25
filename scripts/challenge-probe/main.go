// Challenge-only rate probe.
//
// Every request here is an unauthenticated POST that the server answers with a
// 401 digest challenge. No timestamp is issued, so no quota is consumed, but
// the request travels the same path as a real one: TLS, the servlet, session
// creation, nonce generation.
//
// It exists to separate two explanations for a capacity ceiling. If latency
// bends at the same *request* rate as the timestamp ladder did (~200-250/s,
// since each timestamp costs two requests), the limit is request handling and
// the timestamp rate is simply half of it. If challenges scale well past that,
// the limit is in issuing timestamps - signing, or whatever guards it - and
// the ~100-125/s ceiling is real regardless of how authentication is arranged.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

func main() {
	url := flag.String("url", "", "endpoint (required)")
	ca := flag.String("ca", "", "PEM trust anchor for the TLS connection")
	secs := flag.Int("seconds", 20, "duration of each step")
	flag.Parse()

	// No default endpoint, by the same rule the main tool follows: this sends
	// real traffic, so the target is always named explicitly.
	if *url == "" {
		fmt.Fprintln(os.Stderr, "usage: challenge-probe --url https://tsa.example.invalid [--ca root.pem] [--seconds 20]")
		os.Exit(2)
	}

	rates := []int{100, 150, 200, 250, 300, 400}

	pool := x509.NewCertPool()
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read CA:", err)
			os.Exit(1)
		}
		pool.AppendCertsFromPEM(pem)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxConnsPerHost:     2000,
			MaxIdleConns:        2000,
			MaxIdleConnsPerHost: 2000,
			ForceAttemptHTTP2:   false,
		},
	}

	fmt.Printf("%-8s %-8s %-9s %-9s %-9s %-9s %s\n",
		"istek/s", "gönderi", "401", "p50", "p95", "p99", "diğer")
	for _, rate := range rates {
		step(client, *url, rate, *secs)
	}
}

func step(client *http.Client, url string, rate, secs int) {
	var (
		mu      sync.Mutex
		lat     []time.Duration
		got401  int
		other   = map[string]int{}
		wg      sync.WaitGroup
		total   = rate * secs
		tick    = time.Duration(int64(time.Second) / int64(rate))
		ticker  = time.NewTicker(tick)
		started = time.Now()
	)
	defer ticker.Stop()

	for i := 0; i < total; i++ {
		<-ticker.C
		wg.Add(1)
		go func() {
			defer wg.Done()
			t0 := time.Now()
			req, _ := http.NewRequest(http.MethodPost, url, nil)
			req.Header.Set("Content-Type", "application/timestamp-query")
			req.ContentLength = 0
			resp, err := client.Do(req)
			d := time.Since(t0)

			mu.Lock()
			defer mu.Unlock()
			lat = append(lat, d)
			if err != nil {
				other["error"]++
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				got401++
			} else {
				other[fmt.Sprintf("HTTP %d", resp.StatusCode)]++
			}
		}()
	}
	wg.Wait()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := int(q * float64(len(lat)-1))
		return float64(lat[i].Microseconds()) / 1000
	}
	achieved := float64(len(lat)) / time.Since(started).Seconds()
	fmt.Printf("%-8d %-8.1f %-9d %-9.1f %-9.1f %-9.1f %v\n",
		rate, achieved, got401, p(0.50), p(0.95), p(0.99), other)
}
