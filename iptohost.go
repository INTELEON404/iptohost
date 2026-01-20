package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	VERSION     = "1.2.1"
	TOOL_NAME   = "iptohost"
	BANNER      = `
 ┬┌─┐┌┬┐┌─┐┬ ┬┌─┐┌─┐┌┬┐
 │├─┘ │ │ │├─┤│ │└─┐ │ 
 ┴┴   ┴ └─┘┴ ┴└─┘└─┘ ┴  v%s
`
)

type Result struct {
	Type      string `json:"type"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Timestamp string `json:"timestamp,omitempty"`
	Port      string `json:"port,omitempty"`
	Source    string `json:"source,omitempty"`
}

type Stats struct {
	sync.Mutex
	TotalIPs     int
	SSLHosts     int
	DNSHosts     int
	UniqueHosts  int
	FailedChecks int
	StartTime    time.Time
}

type Config struct {
	Workers      int
	InputFile    string
	OutputFile   string
	ResolverIP   string
	ResolverPort int
	DNSProtocol  string
	DNSTimeout   int
	SNI          string
	Insecure     bool
	JSONOutput   bool
	Timestamped  bool
	Delay        time.Duration
	HTTPTimeout  int
	ShowStats    bool
	Verbose      bool
	Deduplicate  bool
	SkipSSL      bool
	SkipDNS      bool
	Silent       bool
	ShowBanner   bool
}

func (s *Stats) IncrementTotal() {
	s.Lock()
	s.TotalIPs++
	s.Unlock()
}

func (s *Stats) IncrementSSL() {
	s.Lock()
	s.SSLHosts++
	s.Unlock()
}

func (s *Stats) IncrementDNS() {
	s.Lock()
	s.DNSHosts++
	s.Unlock()
}

func (s *Stats) IncrementFailed() {
	s.Lock()
	s.FailedChecks++
	s.Unlock()
}

func (s *Stats) SetUnique(count int) {
	s.Lock()
	s.UniqueHosts = count
	s.Unlock()
}

func (s *Stats) Print(w io.Writer) {
	s.Lock()
	defer s.Unlock()
	
	elapsed := time.Since(s.StartTime)
	rate := float64(s.TotalIPs) / elapsed.Seconds()
	
	fmt.Fprintf(w, "\n╔════════════════════════════════════════════╗\n")
	fmt.Fprintf(w, "║           Statistics Report                ║\n")
	fmt.Fprintf(w, "╠════════════════════════════════════════════╣\n")
	fmt.Fprintf(w, "║ Total IPs processed:    %-18d ║\n", s.TotalIPs)
	fmt.Fprintf(w, "║ SSL hostnames found:    %-18d ║\n", s.SSLHosts)
	fmt.Fprintf(w, "║ DNS PTR records:        %-18d ║\n", s.DNSHosts)
	fmt.Fprintf(w, "║ Unique hostnames:       %-18d ║\n", s.UniqueHosts)
	fmt.Fprintf(w, "║ Failed checks:          %-18d ║\n", s.FailedChecks)
	fmt.Fprintf(w, "║ Time elapsed:           %-18s ║\n", elapsed.Round(time.Millisecond))
	fmt.Fprintf(w, "║ Processing rate:        %-13.2f IPs/s ║\n", rate)
	fmt.Fprintf(w, "╚════════════════════════════════════════════╝\n")
}

func extractPort(ip string) (string, string) {
	ip = strings.TrimPrefix(ip, "http://")
	ip = strings.TrimPrefix(ip, "https://")
	
	if strings.Contains(ip, ":") {
		parts := strings.SplitN(ip, ":", 2)
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return ip, ""
}

func normalizeIP(ip string) string {
	cleanIP, _ := extractPort(ip)
	return cleanIP
}

func buildURL(ip string, port string) string {
	if port != "" && port != "443" {
		return fmt.Sprintf("https://%s:%s", ip, port)
	}
	return fmt.Sprintf("https://%s", ip)
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func sslChecks(ip string, resChan chan<- Result, client *http.Client, config *Config) {
	cleanIP, port := extractPort(ip)
	if port == "" {
		port = "443"
	}
	
	url := buildURL(cleanIP, port)
	
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		if config.Verbose {
			log.Printf("[SSL] Failed to create request for %s: %v", url, err)
		}
		return
	}
	
	req.Header.Set("User-Agent", fmt.Sprintf("%s/%s", TOOL_NAME, VERSION))
	req.Header.Set("Accept", "*/*")
	
	if config.SNI != "" {
		req.Host = config.SNI
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.HTTPTimeout)*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		if config.Verbose {
			log.Printf("[SSL] Failed to connect to %s: %v", url, err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		if config.Verbose {
			log.Printf("[SSL] No TLS certificates found for %s", url)
		}
		return
	}

	cert := resp.TLS.PeerCertificates[0]
	ts := ""
	if config.Timestamped {
		ts = time.Now().Format(time.RFC3339)
	}

	seen := make(map[string]bool)
	
	// Process SANs
	for _, name := range cert.DNSNames {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			resChan <- Result{
				Type:      "SSL-SAN",
				IP:        cleanIP,
				Hostname:  name,
				Timestamp: ts,
				Port:      port,
				Source:    "certificate",
			}
		}
	}
	
	// Process CN
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn != "" && !seen[cn] {
		resChan <- Result{
			Type:      "SSL-CN",
			IP:        cleanIP,
			Hostname:  cn,
			Timestamp: ts,
			Port:      port,
			Source:    "certificate",
		}
	}
}

func dnsChecks(ip string, resChan chan<- Result, resolver *net.Resolver, config *Config) {
	cleanIP := normalizeIP(ip)
	
	if !isValidIP(cleanIP) {
		if config.Verbose {
			log.Printf("[DNS] Invalid IP address: %s", cleanIP)
		}
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.DNSTimeout)*time.Second)
	defer cancel()
	
	addrs, err := resolver.LookupAddr(ctx, cleanIP)
	if err != nil {
		if config.Verbose {
			log.Printf("[DNS] PTR lookup failed for %s: %v", cleanIP, err)
		}
		return
	}
	
	ts := ""
	if config.Timestamped {
		ts = time.Now().Format(time.RFC3339)
	}
	
	for _, addr := range addrs {
		addr = strings.TrimSuffix(strings.TrimSpace(addr), ".")
		if addr != "" {
			resChan <- Result{
				Type:      "DNS-PTR",
				IP:        cleanIP,
				Hostname:  addr,
				Timestamp: ts,
				Source:    "dns",
			}
		}
	}
}

func worker(jobChan <-chan string, resChan chan<- Result, wg *sync.WaitGroup, 
	client *http.Client, resolver *net.Resolver, config *Config, stats *Stats) {
	defer wg.Done()
	
	for job := range jobChan {
		job = strings.TrimSpace(job)
		if job == "" || strings.HasPrefix(job, "#") {
			continue
		}
		
		stats.IncrementTotal()
		
		func() {
			defer func() {
				if r := recover(); r != nil {
					stats.IncrementFailed()
					if config.Verbose {
						log.Printf("[ERROR] Panic processing %s: %v", job, r)
					}
				}
			}()
			
			if !config.SkipSSL {
				sslChecks(job, resChan, client, config)
			}
			
			if !config.SkipDNS {
				dnsChecks(job, resChan, resolver, config)
			}
		}()
	}
}

func createHTTPClient(config *Config) *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
			MinVersion:         tls.VersionTLS10,
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   config.Workers,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
	}

	return &http.Client{
		Timeout:   time.Duration(config.HTTPTimeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func createResolver(config *Config) *net.Resolver {
	if config.ResolverIP == "" {
		return net.DefaultResolver
	}
	
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Duration(config.DNSTimeout) * time.Second}
			return d.DialContext(ctx, config.DNSProtocol, 
				fmt.Sprintf("%s:%d", config.ResolverIP, config.ResolverPort))
		},
	}
}

func writeResult(w io.Writer, res Result, config *Config) {
	if config.JSONOutput {
		jsonData, _ := json.Marshal(res)
		fmt.Fprintln(w, string(jsonData))
	} else if config.Silent {
		fmt.Fprintln(w, res.Hostname)
	} else {
		if config.Timestamped && res.Timestamp != "" {
			if res.Port != "" && res.Port != "443" {
				fmt.Fprintf(w, "[%s] %s:%s -> %s [%s]\n", 
					res.Type, res.IP, res.Port, res.Hostname, res.Timestamp)
			} else {
				fmt.Fprintf(w, "[%s] %s -> %s [%s]\n", 
					res.Type, res.IP, res.Hostname, res.Timestamp)
			}
		} else {
			if res.Port != "" && res.Port != "443" {
				fmt.Fprintf(w, "[%s] %s:%s -> %s\n", 
					res.Type, res.IP, res.Port, res.Hostname)
			} else {
				fmt.Fprintf(w, "[%s] %s -> %s\n", 
					res.Type, res.IP, res.Hostname)
			}
		}
	}
}

func printBanner() {
	fmt.Fprintf(os.Stderr, BANNER, VERSION)
	fmt.Fprintln(os.Stderr)
}

func main() {
	config := &Config{}
	
	flag.IntVar(&config.Workers, "t", 32, "Number of concurrent workers")
	flag.IntVar(&config.Workers, "threads", 32, "Number of concurrent workers (alias)")
	flag.StringVar(&config.InputFile, "i", "", "Input file containing IPs (default: stdin)")
	flag.StringVar(&config.OutputFile, "o", "", "Output file for results (default: stdout)")
	flag.StringVar(&config.ResolverIP, "r", "", "Custom DNS resolver IP address")
	flag.StringVar(&config.ResolverIP, "resolver", "", "Custom DNS resolver IP address (alias)")
	flag.IntVar(&config.ResolverPort, "p", 53, "DNS resolver port")
	flag.StringVar(&config.DNSProtocol, "protocol", "udp", "DNS protocol (udp/tcp)")
	flag.IntVar(&config.DNSTimeout, "dns-timeout", 5, "DNS lookup timeout in seconds")
	flag.StringVar(&config.SNI, "sni", "", "Override SNI hostname for SSL connections")
	flag.BoolVar(&config.Insecure, "insecure", true, "Skip TLS certificate verification")
	flag.BoolVar(&config.JSONOutput, "json", false, "Output results as JSON")
	flag.BoolVar(&config.Timestamped, "timestamp", false, "Add RFC3339 timestamps to results")
	delayStr := flag.String("delay", "0s", "Delay between requests (e.g., 100ms, 1s)")
	flag.IntVar(&config.HTTPTimeout, "timeout", 10, "HTTP client timeout in seconds")
	flag.BoolVar(&config.ShowStats, "stats", false, "Show statistics summary at completion")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output with debug information")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output with debug information (alias)")
	flag.BoolVar(&config.Deduplicate, "dedupe", false, "Deduplicate hostnames in output")
	flag.BoolVar(&config.SkipSSL, "skip-ssl", false, "Skip SSL certificate checks")
	flag.BoolVar(&config.SkipDNS, "skip-dns", false, "Skip DNS PTR lookups")
	flag.BoolVar(&config.Silent, "silent", false, "Silent mode - only output hostnames")
	flag.BoolVar(&config.Silent, "s", false, "Silent mode - only output hostnames (alias)")
	flag.BoolVar(&config.ShowBanner, "banner", false, "Show banner on startup")
	version := flag.Bool("version", false, "Show version information")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s v%s - IP to Hostname Discovery Tool\n\n", TOOL_NAME, VERSION)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  Basic usage:\n")
		fmt.Fprintf(os.Stderr, "    cat ips.txt | %s\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "    echo '1.1.1.1' | %s\n\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "  Advanced options:\n")
		fmt.Fprintf(os.Stderr, "    %s -i ips.txt -o results.txt -t 50 -stats\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "    %s -i ips.txt -json -dedupe -silent\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "    %s -i ips.txt -r 8.8.8.8 -v -delay 100ms\n\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "  Specialized scans:\n")
		fmt.Fprintf(os.Stderr, "    %s -skip-dns -t 100          # SSL only\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "    %s -skip-ssl -r 1.1.1.1      # DNS only\n", TOOL_NAME)
		fmt.Fprintf(os.Stderr, "    %s -sni example.com -insecure=false\n", TOOL_NAME)
	}
	
	flag.Parse()

	if *version {
		fmt.Printf("%s version %s\n", TOOL_NAME, VERSION)
		return
	}

	if config.ShowBanner {
		printBanner()
	}

	var err error
	config.Delay, err = time.ParseDuration(*delayStr)
	if err != nil {
		log.Fatalf("[!] Invalid delay format: %v", err)
	}

	if config.SkipSSL && config.SkipDNS {
		log.Fatal("[!] Cannot skip both SSL and DNS checks")
	}

	var input io.Reader = os.Stdin
	if config.InputFile != "" {
		file, err := os.Open(config.InputFile)
		if err != nil {
			log.Fatalf("[!] Failed to open input file: %v", err)
		}
		defer file.Close()
		input = file
	}

	var output io.Writer = os.Stdout
	if config.OutputFile != "" {
		file, err := os.Create(config.OutputFile)
		if err != nil {
			log.Fatalf("[!] Failed to create output file: %v", err)
		}
		defer file.Close()
		output = file
	}

	if config.Verbose && !config.Silent {
		log.Printf("[*] Starting %s v%s", TOOL_NAME, VERSION)
		log.Printf("[*] Workers: %d", config.Workers)
		log.Printf("[*] SSL checks: %v", !config.SkipSSL)
		log.Printf("[*] DNS checks: %v", !config.SkipDNS)
		if config.ResolverIP != "" {
			log.Printf("[*] Custom resolver: %s:%d (%s)", config.ResolverIP, config.ResolverPort, config.DNSProtocol)
		}
	}

	stats := &Stats{StartTime: time.Now()}
	client := createHTTPClient(config)
	resolver := createResolver(config)

	jobChan := make(chan string, config.Workers*2)
	resChan := make(chan Result, config.Workers*4)
	var wg sync.WaitGroup

	wg.Add(config.Workers)
	for i := 0; i < config.Workers; i++ {
		go worker(jobChan, resChan, &wg, client, resolver, config, stats)
	}

	go func() {
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				jobChan <- line
				if config.Delay > 0 {
					time.Sleep(config.Delay)
				}
			}
		}
		
		if err := scanner.Err(); err != nil {
			log.Printf("[!] Scanner error: %v", err)
		}
		
		close(jobChan)
	}()

	go func() {
		wg.Wait()
		close(resChan)
	}()

	seenHosts := make(map[string]bool)
	
	for res := range resChan {
		if config.Deduplicate && seenHosts[res.Hostname] {
			continue
		}
		
		if config.Deduplicate {
			seenHosts[res.Hostname] = true
		}
		
		if strings.HasPrefix(res.Type, "SSL-") {
			stats.IncrementSSL()
		} else if res.Type == "DNS-PTR" {
			stats.IncrementDNS()
		}
		
		writeResult(output, res, config)
		
		if config.Verbose && !config.Silent {
			log.Printf("[+] FOUND: %s -> %s", res.IP, res.Hostname)
		}
	}

	if config.ShowStats {
		stats.SetUnique(len(seenHosts))
		if !config.Deduplicate {
			stats.Lock()
			stats.UniqueHosts = stats.SSLHosts + stats.DNSHosts
			stats.Unlock()
		}
		stats.Print(os.Stderr)
	}
}
