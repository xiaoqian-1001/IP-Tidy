package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	inputFile   = flag.String("i", "", "IP list file (required)")
	outputFile  = flag.String("o", "", "Output file for CF proxy hits (default: cf_hits_<timestamp>.txt)")
	stateFile   = flag.String("state", "scanner.state", "Checkpoint file for resume")
	concurrency = flag.Int("c", 500, "Concurrent connections")
	connectTO   = flag.Duration("connect-timeout", 1500*time.Millisecond, "TCP+TLS connect timeout")
	totalTO     = flag.Duration("timeout", 2*time.Second, "Total request timeout")
	port        = flag.String("p", "443", "Target port")
	sni         = flag.String("sni", "cloudflare.com", "TLS SNI to send")
	host        = flag.String("host", "www.cloudflare.com", "HTTP Host header")
)

type result struct {
	target string
	reason string
}

func isCloudflareProxy(ip string, client *http.Client) (bool, string, string) {
	targetHost, targetPort := ip, *port
	if h, p, err := net.SplitHostPort(ip); err == nil {
		targetHost, targetPort = h, p
	}
	target := net.JoinHostPort(targetHost, targetPort)

	ctx, cancel := context.WithTimeout(context.Background(), *totalTO)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+target+"/", nil)
	if err != nil {
		return false, "", target
	}
	req.Host = *host
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return false, "", target
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	cfRay := resp.Header.Get("CF-RAY")

	if serverHeader == "cloudflare" || cfRay != "" {
		reason := fmt.Sprintf("status=%d", resp.StatusCode)
		if serverHeader == "cloudflare" {
			reason += " server=cloudflare"
		}
		if cfRay != "" {
			reason += " cf-ray=" + cfRay[:min(len(cfRay), 30)]
		}
		return true, reason, target
	}

	return false, "", target
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if scanner.Text() != "" {
			count++
		}
	}
	return count, scanner.Err()
}

func streamLines(ctx context.Context, path string, skip int, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		lineNum++
		if lineNum <= skip {
			continue
		}
		select {
		case out <- line:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return scanner.Err()
}

func writeState(path string, inputFile string, scanned int) {
	data := fmt.Sprintf("%s\t%d", inputFile, scanned)
	_ = os.WriteFile(path, []byte(data), 0644)
}

func main() {
	flag.Parse()
	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: cf-scanner -i ips.txt [-o hits.txt] [-c 500]")
		os.Exit(1)
	}

	if *outputFile == "" {
		*outputFile = fmt.Sprintf("cf_hits_%s.txt", time.Now().Format("20060102_150405"))
	}
	fmt.Printf("Output: %s\n", *outputFile)

	fmt.Print("Counting IPs... ")
	total, err := countLines(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed to read %s: %v\n", *inputFile, err)
		os.Exit(1)
	}
	fmt.Printf("%d\n", total)

	skip := 0
	if data, err := os.ReadFile(*stateFile); err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(data)), "\t", 2)
		if len(parts) == 2 && parts[0] == *inputFile {
			fmt.Sscanf(parts[1], "%d", &skip)
			if skip > 0 && skip < total {
				fmt.Printf("Resuming from line %d (%.1f%% done)\n",
					skip, float64(skip)/float64(total)*100)
			} else {
				skip = 0
			}
		} else {
			fmt.Printf("State file is for %q, not %q - starting fresh\n",
				parts[0], *inputFile)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         *sni,
		},
		DialContext: (&net.Dialer{
			Timeout: *connectTO,
		}).DialContext,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		IdleConnTimeout:     1 * time.Second,
		DisableKeepAlives:   true,
	}

	out, err := os.OpenFile(*outputFile, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s: %v\n", *outputFile, err)
		os.Exit(1)
	}
	defer out.Close()

	var (
		scanned  atomic.Int64
		hitCount atomic.Int64
		wg       sync.WaitGroup
		stateMu  sync.Mutex
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "\nReceived %v, saving state and exiting...\n", sig)
		writeState(*stateFile, *inputFile, skip+int(scanned.Load()))
		cancel()
	}()

	jobs := make(chan string, *concurrency*2)
	results := make(chan result, *concurrency)

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Transport: transport,
				Timeout:   *totalTO,
			}
			for ip := range jobs {
				ok, reason, target := isCloudflareProxy(ip, client)
				n := scanned.Add(1)
				if ok {
					select {
					case results <- result{target, reason}:
					case <-ctx.Done():
						return
					}
				}
				if n%1000 == 0 {
					stateMu.Lock()
					writeState(*stateFile, *inputFile, skip+int(n))
					stateMu.Unlock()
				}
			}
		}()
	}

	go func() {
		for r := range results {
			hitCount.Add(1)
			fmt.Fprintf(out, "%s  %s\n", r.target, r.reason)
			out.Sync()
		}
	}()

	startTime := time.Now()
	startSkip := int64(skip)
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				n := scanned.Load()
				elapsed := time.Since(startTime)
				rate := float64(n) / elapsed.Seconds()
				remain := int64(total) - startSkip - n
				var eta time.Duration
				if rate > 0 {
					eta = time.Duration(float64(remain)/rate) * time.Second
				}
				pct := float64(startSkip+n) / float64(total) * 100
				fmt.Printf("\r\033[KScanned %d/%d (%.1f%%) | %.0f/s | hits=%d | ETA %s",
					startSkip+n, total, pct, rate, hitCount.Load(), eta.Round(time.Second))
			}
		}
	}()

	go func() {
		if err := streamLines(ctx, *inputFile, skip, jobs); err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "\nError reading input: %v\n", err)
		}
		close(jobs)
	}()

	wg.Wait()
	close(results)
	close(done)

	writeState(*stateFile, *inputFile, total)

	elapsed := time.Since(startTime)
	fmt.Printf("\r\033[KDone! %d/%d (100%%) | %s | hits=%d\n",
		total, total, elapsed.Round(time.Second), hitCount.Load())
	fmt.Printf("Results: %s (%d hits)\n", *outputFile, hitCount.Load())
	os.Remove(*stateFile)
}
