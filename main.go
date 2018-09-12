package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"net/http"
	_ "net/http/pprof"
)

var wordList []string

var outputType string

// Whether this is the first line of output to print
var outputFirst bool
var zt bool
var maxDepth int

func main() {
	go func() {
		http.ListenAndServe("localhost:6061", http.DefaultServeMux)
	}()
	// Parse cmdline
	flag_domain := flag.String("domain", "", "The target domain")
	flag_wordlist := flag.String("wordlist", "wordlist.txt", "Path to the wordlist")
	flag_threads := flag.Int("threads", 20, "Number of concurrent threads")
	flag_output := flag.String("output", "csv", "Output type (csv, json)")
	flag_zt := flag.Bool("zt", false, "Zone Transfer")
	flag_depth := flag.Int("depth", 0, "Depth to ignore wildcards/NX and continue bruteforce")

	flag.Parse()

	if *flag_domain == "" {
		fmt.Fprint(os.Stderr, "You must specify a domain\r\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *flag_zt {
		zt = true
	}

	if *flag_depth > 0 {
		maxDepth = *flag_depth
	}

	outputType = strings.ToLower(*flag_output)
	outputFirst = true

	switch outputType {
	case "csv":
	case "json":
		fmt.Printf("{\r\n")
		defer fmt.Printf("\r\n}")
	default:
		fmt.Fprintf(os.Stderr, "Invalid output format specified\r\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	file, err := os.Open(*flag_wordlist)
	if err != nil {
		panic(err)
	}

	// TODO: Move a few of these operations to the resolveList function - DRY
	// Check for wildcard record(s) before starting
	wildcard := checkWildcard(*flag_domain)

	// Check for zone transfer
	if checkZoneTransfer(*flag_domain) {
		// No need to continue in this case
		// TODO: This will change when we recursively do checkZoneTransfers etc
		// That will require a slight restructuring of the code, but should be simple enough
		// See the note about DRY refactor
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordList = append(wordList, scanner.Text())
	}
	cnt := math.Pow(float64(len(wordList)), float64(maxDepth))
	for x := float64(0); x < float64(maxDepth)-1; x++ {
		cnt = cnt + math.Pow(float64(len(wordList)), x)
	}
	fmt.Println("Looking up", cnt, "domains")
	wg := &sync.WaitGroup{}
	wg.Add(1)
	queue := make(chan struct{}, *flag_threads)
	resolveList(wg, queue, *flag_domain, wildcard, 0)
	wg.Wait()
}

func resolveList(wg *sync.WaitGroup, queue chan struct{}, apex string, wildcard []string, depth int) {
	//fmt.Println(depth, apex)
	defer wg.Done()
	// Create a waitgroup for all of the child threads we'll spawn
	for i := range wordList {
		domainName := fmt.Sprintf("%s.%s", wordList[i], apex)

		queue <- struct{}{}
		// wait for free worker thread
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Add an item to the WaitGroup
			// Defer removing ourselves from the WaitGroup once we're complete
			ips, err := net.LookupHost(domainName)
			// we have looked up the host, so we can remove this item from the queue
			// so that another go routine can give it a go
			<-queue

			// did not resolve
			if err != nil {
				// TODO: find a nicer way of writing this
				errstr := err.Error()
				nsh := "no such host"
				if errstr[len(errstr)-len(nsh):] != nsh {
					fmt.Fprintf(os.Stderr, "Unexpected error: %v\n", err)
					return
				}
				if maxDepth == 0 {
					return
				}
			}

			// Check if it's a wildcard
			if len(wildcard) > 0 && maxDepth != 0 {
				if reflect.DeepEqual(ips, wildcard) {
					return
				}
			}

			// we found a non-wildcard sub domain, recurse
			if checkZoneTransfer(domainName) {
				// No need to make the requests manually
				return
			}
			for _, ip := range ips {
				outputResult(domainName, "A", ip)
			}
			if maxDepth != 0 && depth < maxDepth {
				wg.Add(1)
				resolveList(wg, queue, domainName, checkWildcard(domainName), depth+1)
			}

		}()
		// wait for child to finish
		// Wait for all children to complete

		// Signal we're done
	}
}

func checkWildcard(domain string) (wildcard []string) {
	// Check for wildcard record(s)
	randomString := randomString(10)
	wildcard, _ = net.LookupHost(randomString + "." + domain)
	if len(wildcard) > 0 {
		fmt.Fprintf(os.Stderr, "Detected wildcard record: %s\r\n", domain)
	}
	return
}

func resolveName(domain string) {

}

func checkZoneTransfer(domain string) (success bool) {
	if zt {
		// TODO: Add the ability to not attempt zoneTransfers
		success = false // failure by default

		// Find all nameservers for the AXFR attempt
		nss, err := net.LookupNS(domain)
		if err != nil {
			// Don't bother reporting the error if there were no nameservers in the first place
			//fmt.Fprintf(os.Stderr, "Error finding nameservers for %s: %s\r\n", domain, err)
			return
		}
		if len(nss) == 0 {
			fmt.Fprintf(os.Stderr, "Error finding a nameserver for %s\r\n", domain)
			return
		}

		// Create our messages and client
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))
		// Explicitly create a client to use TCP
		c := new(dns.Client)
		c.Net = "tcp"

		// Loop over each of the nameservers
		for _, ns := range nss {
			in, _, err := c.Exchange(m, ns.Host+":53")

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error attempting zone transfer for %s using nameserver %s: %s\r\n", domain, ns.Host, err)
				continue
			}

			if len(in.Answer) == 0 {
				// Expected failure of zone transfer
				fmt.Fprintf(os.Stderr, "Zone transfer failed for %s using nameserver %s\r\n", domain, ns.Host)
				continue
			}

			fmt.Fprintf(os.Stderr, "Zone transfer successful for %s using nameserver %s\r\n", domain, ns.Host)

			// TODO: We need to identify subzones that might be handled by different nameservers and recurse on those too
			for _, record := range in.Answer {
				// detect type of record
				switch t := record.(type) {
				case *dns.A:
					outputResult(t.Header().Name, "A", t.A.String())
				case *dns.CNAME:
					outputResult(t.Header().Name, "CNAME", t.Target)
				case *dns.TXT:
					for _, txt := range t.Txt {
						outputResult(t.Header().Name, "TXT", txt)
					}
				default:
					fmt.Fprintf(os.Stderr, "Unable to detect type of entry in zonetransfer: %s\r\n", record)
				}
			}

			// no need to continue querying additional nameservers, just return
			return true
		}
		return
	}
	return false
}

func outputResult(domain string, shortName string, value string) {
	switch outputType {
	case "json":
		if outputFirst {
			outputFirst = false
		} else {
			fmt.Printf(",\r\n")
		}
		fmt.Printf("{\"%s\": {\"%s\", \"%s\"}}", domain, shortName, value)
	case "csv":
		fmt.Printf("%s,%s,%s\r\n", domain, shortName, value)
	}
}

func randomString(length int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
