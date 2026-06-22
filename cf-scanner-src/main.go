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

const version = "1.3.0"

var (
	inputFile   = flag.String("i", "", "IP:port list file (required)")
	outputFile  = flag.String("o", "", "Output file (default: cf_hits_<timestamp>.txt)")
	stateFile   = flag.String("state", "scanner.state", "Checkpoint file for resume")
	concurrency = flag.Int("c", 500, "Concurrent connections")
	connectTO   = flag.Duration("connect-timeout", 1500*time.Millisecond, "TCP+TLS connect timeout")
	totalTO     = flag.Duration("timeout", 2*time.Second, "Total request timeout")
	port        = flag.String("p", "443", "Default target port")
	sni         = flag.String("sni", "cloudflare.com", "TLS SNI to send")
	hostHdr     = flag.String("host", "www.cloudflare.com", "HTTP Host header")
	showVersion = flag.Bool("version", false, "Print version and exit")
)

type result struct {
	line string
}

func isCloudflareProxy(ip string, client *http.Client) (bool, string) {
	targetHost, targetPort := ip, *port
	if h, p, err := net.SplitHostPort(ip); err == nil {
		targetHost, targetPort = h, p
	}
	target := net.JoinHostPort(targetHost, targetPort)

	ctx, cancel := context.WithTimeout(context.Background(), *totalTO)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+target+"/", nil)
	if err != nil {
		return false, target
	}
	req.Host = *hostHdr
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Close = true

	resp, err := client.Do(req)
	if err != nil {
		return false, target
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
		return true, fmt.Sprintf("%s  %s", target, reason)
	}
	return false, target
}

func loadLines(path string) ([]string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, len(lines), scanner.Err()
}

func writeState(path, inputFile string, scanned int) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%s\t%d", inputFile, scanned)), 0644)
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("cf-scanner %s\n", version)
		os.Exit(0)
	}
	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage: cf-scanner -i ips.txt [-o hits.txt] [-c 500]")
		fmt.Fprintf(os.Stderr, "       cf-scanner --version\n")
		os.Exit(1)
	}

	if *outputFile == "" {
		*outputFile = fmt.Sprintf("cf_hits_%s.txt", time.Now().Format("20060102_150405"))
	}
	fmt.Printf("Output: %s\n", *outputFile)

	skip := 0
	if data, err := os.ReadFile(*stateFile); err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(data)), "\t", 2)
		if len(parts) == 2 && parts[0] == *inputFile {
			fmt.Sscanf(parts[1], "%d", &skip)
		}
	}

	fmt.Print("Loading... ")
	allLines, totalCount, err := loadLines(*inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nFailed: %v\n", err)
		os.Exit(1)
	}
	if skip > totalCount {
		skip = 0
	}
	fmt.Printf("%d total", totalCount)
	if skip > 0 {
		fmt.Printf(" (resume from %d)", skip)
	}
	fmt.Println()

	feed := allLines
	if skip > 0 && skip < len(allLines) {
		feed = allLines[skip:]
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         *sni,
		},
		DialContext:       (&net.Dialer{Timeout: *connectTO}).DialContext,
		DisableKeepAlives: true,
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
		total    = int64(len(feed) + skip)
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Fprintf(os.Stderr, "\nReceived %v, saving state...\n", sig)
		writeState(*stateFile, *inputFile, skip+int(scanned.Load()))
		cancel()
	}()

	jobs := make(chan string, *concurrency*2)
	results := make(chan result, *concurrency)

	sharedClient := &http.Client{Transport: transport, Timeout: *totalTO}

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ok, line := isCloudflareProxy(ip, sharedClient)
				n := scanned.Add(1)
				if ok {
					select {
					case results <- result{line}:
					case <-ctx.Done():
						return
					}
				}
				if n%1000 == 0 {
					stateMu.Lock()
					_ = writeState(*stateFile, *inputFile, skip+int(n))
					stateMu.Unlock()
				}
			}
		}()
	}

	go func() {
		for r := range results {
			hitCount.Add(1)
			if _, err := fmt.Fprintln(out, r.line); err != nil {
				fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
			}
		}
		out.Sync()
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
				remain := total - startSkip - n
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
		for _, line := range feed {
			select {
			case jobs <- line:
			case <-ctx.Done():
				return
			}
		}
		close(jobs)
	}()

	wg.Wait()
	close(results)
	close(done)

	_ = writeState(*stateFile, *inputFile, int(total))

	elapsed := time.Since(startTime)
	fmt.Printf("\r\033[KDone! %d/%d (100%%) | %s | hits=%d\n",
		total, total, elapsed.Round(time.Second), hitCount.Load())
	fmt.Printf("Results: %s (%d hits)\n", *outputFile, hitCount.Load())
	os.Remove(*stateFile)
}
