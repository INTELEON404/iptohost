package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const VERSION = "1.2.1"

type Result struct {
	Type      string `json:"type"`
	IP        string `json:"ip"`
	Data      string `json:"data"`
	Timestamp string `json:"timestamp,omitempty"`
}

type Stats struct {
	TotalIPs     int `json:"total_ips"`
	SSLHosts     int `json:"ssl_hosts"`
	DNSHosts     int `json:"dns_hosts"`
	UniqueHosts  int `json:"unique_hosts"`
	FailedChecks int `json:"failed_checks"`
}

// SSL checks: extract SAN and CN with improved error handling
func sslChecks(ip string, resChan chan<- Result, client *http.Client, sni string, insecure bool, timestamped bool) {
	url := ip
	if strings.HasPrefix(ip, "http://") {
		url = strings.Replace(ip, "http://", "https://", 1)
	} else if !strings.HasPrefix(ip, "https://") {
		url = "https://" + ip
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "hakip2host/1.2.1")
	if sni != "" {
		req.Host = sni
	}

	resp, err := client.Do(req)
	if err != nil {
		// fallback GET
		reqGet, errGet := http.NewRequest("GET", url, nil)
		if errGet != nil {
			return
		}
		reqGet.Header.Set("User-Agent", "hakip2host/1.2.1")
		if sni != "" {
			reqGet.Host = sni
		}
		resp, err = client.Do(reqGet)
		if err != nil {
			return
		}
	}
	defer resp.Body.Close()

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		ts := ""
		if timestamped {
			ts = time.Now().Format(time.RFC3339)
		}

		seen := make(map[string]bool)
		for _, name := range cert.DNSNames {
			if !seen[name] {
				seen[name] = true
				resChan <- Result{Type: "SSL-SAN", IP: ip, Data: name, Timestamp: ts}
			}
		}
		if cert.Subject.CommonName != "" && !seen[cert.Subject.CommonName] {
			resChan <- Result{Type: "SSL-CN", IP: ip, Data: cert.Subject.CommonName, Timestamp: ts}
		}
	}
}

// DNS PTR lookup with timeout context
func dnsChecks(ip string, resChan chan<- Result, resolver *net.Resolver, timestamped bool, dnsTimeout int) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dnsTimeout)*time.Second)
	defer cancel()
	
	addrs, err := resolver.LookupAddr(ctx, ip)
	if err != nil {
		return
	}
	
	ts := ""
	if timestamped {
		ts = time.Now().Format(time.RFC3339)
	}
	
	for _, a := range addrs {
		a = strings.TrimSuffix(a, ".")
		resChan <- Result{Type: "DNS-PTR", IP: ip, Data: a, Timestamp: ts}
	}
}

// Worker goroutine with stats tracking
func worker(jobChan <-chan string, resChan chan<- Result, wg *sync.WaitGroup, client *http.Client, 
	resolver *net.Resolver, sni string, timestamped bool, dnsTimeout int, statsMutex *sync.Mutex, stats *Stats) {
	defer wg.Done()
	for job := range jobChan {
		job = strings.TrimSpace(job)
		if job == "" {
			continue
		}
		func(ip string) {
			defer func() { 
				if r := recover(); r != nil {
					statsMutex.Lock()
					stats.FailedChecks++
					statsMutex.Unlock()
				}
			}()
			
			statsMutex.Lock()
			stats.TotalIPs++
			statsMutex.Unlock()
			
			sslChecks(ip, resChan, client, sni, true, timestamped)
			if net.ParseIP(ip) != nil {
				dnsChecks(ip, resChan, resolver, timestamped, dnsTimeout)
			}
		}(job)
	}
}

func main() {
	workers := flag.Int("t", 32, "number of workers")
	inputFile := flag.String("i", "", "input file (default stdin)")
	outputFile := flag.String("o", "", "output file (default stdout)")
	resolverIP := flag.String("r", "", "DNS resolver IP")
	resolverPort := flag.Int("p", 53, "DNS resolver port")
	dnsProtocol := flag.String("protocol", "udp", "DNS protocol (udp/tcp)")
	dnsTimeout := flag.Int("dns-timeout", 5, "DNS lookup timeout in seconds")
	sni := flag.String("sni", "", "override SNI host for SSL")
	insecure := flag.Bool("insecure", true, "skip TLS verification")
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	timestamped := flag.Bool("timestamp", false, "add timestamp to results")
	delay := flag.String("delay", "0s", "delay between requests, e.g., 100ms")
	timeout := flag.Int("timeout", 10, "HTTP client timeout in seconds")
	showStats := flag.Bool("stats", false, "show statistics at the end")
	version := flag.Bool("version", false, "show version")
	verbose := flag.Bool("v", false, "verbose output")
	deduplicate := flag.Bool("dedupe", false, "deduplicate hostnames in output")
	flag.Parse()

	if *version {
		fmt.Printf("hakip2host version %s\n", VERSION)
		os.Exit(0)
	}

	var scanner *bufio.Scanner
	if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	var output *os.File
	if *outputFile != "" {
		var err error
		output, err = os.Create(*outputFile)
		if err != nil {
			log.Fatal(err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	delayDur, err := time.ParseDuration(*delay)
	if err != nil {
		delayDur = 0
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: *insecure},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Timeout:   time.Duration(*timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var resolver *net.Resolver
	if *resolverIP != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, *dnsProtocol, fmt.Sprintf("%s:%d", *resolverIP, *resolverPort))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	jobChan := make(chan string)
	resChan := make(chan Result, *workers*4)
	var wg sync.WaitGroup
	wg.Add(*workers)

	stats := &Stats{}
	var statsMutex sync.Mutex

	// Start workers
	for i := 0; i < *workers; i++ {
		go worker(jobChan, resChan, &wg, client, resolver, *sni, *timestamped, *dnsTimeout, &statsMutex, stats)
	}

	// Feed jobs
	go func() {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				jobChan <- line
				if delayDur > 0 {
					time.Sleep(delayDur)
				}
			}
		}
		close(jobChan)
	}()

	// Close result channel when done
	go func() {
		wg.Wait()
		close(resChan)
	}()

	// Output results with deduplication
	seenHosts := make(map[string]bool)
	for res := range resChan {
		if *deduplicate && seenHosts[res.Data] {
			continue
		}
		
		if *deduplicate {
			seenHosts[res.Data] = true
		}
		
		if strings.HasPrefix(res.Type, "SSL-") {
			statsMutex.Lock()
			stats.SSLHosts++
			statsMutex.Unlock()
		} else if res.Type == "DNS-PTR" {
			statsMutex.Lock()
			stats.DNSHosts++
			statsMutex.Unlock()
		}
		
		if *jsonOutput {
			jsonData, _ := json.Marshal(res)
			fmt.Fprintln(output, string(jsonData))
		} else {
			if *timestamped && res.Timestamp != "" {
				fmt.Fprintf(output, "[%s] %s %s %s\n", res.Type, res.IP, res.Data, res.Timestamp)
			} else {
				fmt.Fprintf(output, "[%s] %s %s\n", res.Type, res.IP, res.Data)
			}
		}
		
		if *verbose {
			log.Printf("[%s] Found: %s -> %s\n", res.Type, res.IP, res.Data)
		}
	}

	// Show statistics
	if *showStats {
		stats.UniqueHosts = len(seenHosts)
		if !*deduplicate {
			stats.UniqueHosts = stats.SSLHosts + stats.DNSHosts
		}
		
		fmt.Fprintln(os.Stderr, "\n=== Statistics ===")
		fmt.Fprintf(os.Stderr, "Total IPs processed: %d\n", stats.TotalIPs)
		fmt.Fprintf(os.Stderr, "SSL hostnames found: %d\n", stats.SSLHosts)
		fmt.Fprintf(os.Stderr, "DNS PTR records found: %d\n", stats.DNSHosts)
		fmt.Fprintf(os.Stderr, "Unique hostnames: %d\n", stats.UniqueHosts)
		fmt.Fprintf(os.Stderr, "Failed checks: %d\n", stats.FailedChecks)
	}
}
