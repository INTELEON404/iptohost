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

type Result struct {
	Type string `json:"type"`
	IP   string `json:"ip"`
	Data string `json:"data"`
}

// SSL checks: extract SAN and CN
func sslChecks(ip string, resChan chan<- Result, client *http.Client, sni string, insecure bool) {
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
	req.Header.Set("User-Agent", "hakip2host/1.0")
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
		reqGet.Header.Set("User-Agent", "hakip2host/1.0")
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

		for _, name := range cert.DNSNames {
			resChan <- Result{Type: "SSL-SAN", IP: ip, Data: name}
		}
		if cert.Subject.CommonName != "" {
			resChan <- Result{Type: "SSL-CN", IP: ip, Data: cert.Subject.CommonName}
		}
	}
}

// DNS PTR lookup
func dnsChecks(ip string, resChan chan<- Result, resolver *net.Resolver) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupAddr(context.Background(), ip)
	if err != nil {
		return
	}
	for _, a := range addrs {
		a = strings.TrimSuffix(a, ".")
		resChan <- Result{Type: "DNS-PTR", IP: ip, Data: a}
	}
}

// Worker goroutine
func worker(jobChan <-chan string, resChan chan<- Result, wg *sync.WaitGroup, client *http.Client, resolver *net.Resolver, sni string) {
	defer wg.Done()
	for job := range jobChan {
		job = strings.TrimSpace(job)
		if job == "" {
			continue
		}
		func(ip string) {
			defer func() { recover() }()
			sslChecks(ip, resChan, client, sni, true)
			if net.ParseIP(ip) != nil {
				dnsChecks(ip, resChan, resolver)
			}
		}(job)
	}
}

func main() {
	workers := flag.Int("t", 32, "number of workers")
	inputFile := flag.String("i", "", "input file (default stdin)")
	resolverIP := flag.String("r", "", "DNS resolver IP")
	resolverPort := flag.Int("p", 53, "DNS resolver port")
	dnsProtocol := flag.String("protocol", "udp", "DNS protocol (udp/tcp)")
	sni := flag.String("sni", "", "override SNI host for SSL")
	insecure := flag.Bool("insecure", true, "skip TLS verification")
	jsonOutput := flag.Bool("json", false, "output results as JSON")
	delay := flag.String("delay", "0s", "delay between requests, e.g., 100ms")
	timeout := flag.Int("timeout", 10, "HTTP client timeout in seconds")
	flag.Parse()

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

	delayDur, err := time.ParseDuration(*delay)
	if err != nil {
		delayDur = 0
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: *insecure},
	}

	client := &http.Client{
		Timeout:   time.Duration(*timeout) * time.Second,
		Transport: transport,
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

	// Start workers
	for i := 0; i < *workers; i++ {
		go worker(jobChan, resChan, &wg, client, resolver, *sni)
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

	// Output results
	for res := range resChan {
		if *jsonOutput {
			jsonData, _ := json.Marshal(res)
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("[%s] %s %s\n", res.Type, res.IP, res.Data)
		}
	}
}
