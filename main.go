package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var wordList []string

var outputType string

// Whether this is the first line of output to print
var outputFirst bool

// Should we attempt a zone transfer
var zonetransfer bool

// The minimum depth to recurse to regardless of whether results are found
// This can be used to force finding of "hidden" subdomains where x.y.z resolves, but not y.z
var minDepth int

func main() {
	// Parse cmdline
	flag_domain := flag.String("domain", "", "The target domain")
	flag_wordlist := flag.String("wordlist", "wordlist.txt", "Path to the wordlist")
	flag_threads := flag.Int("threads", 20, "Number of concurrent threads")
	flag_output := flag.String("output", "csv", "Output type (csv, json)")
	flag_zonetransfer := flag.Bool("zt", true, "Attempt a zone transfer")
	flag_minDepth := flag.Int("depth", 0, "Depth to ignore wildcards/NX and continue bruteforce (this is a 'minimum', so will find deeper subdomains if it can)")

	flag.Parse()

	if *flag_domain == "" {
		fmt.Fprint(os.Stderr, "You must specify a domain\r\n")
		flag.PrintDefaults()
		os.Exit(1)
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

	zonetransfer = *flag_zonetransfer

	if *flag_minDepth < 0 {
		fmt.Fprintf(os.Stderr, "Invalid depth detected. Must be 0 or greater")
		os.Exit(1)
	}
	minDepth = *flag_minDepth
	currentDepth := 0

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

	queue := make(chan string, *flag_threads)
	done := resolveList(queue, *flag_domain, wildcard, currentDepth)
	<-done
}

func resolveList(queue chan string, apex string, wildcard []string, currentDepth int) chan bool {
	doneChan := make(chan bool)
	go func() {
		// Create a waitgroup for all of the child threads we'll spawn
		var childrenWait sync.WaitGroup
		for i := range wordList {
			domainName := fmt.Sprintf("%s.%s", wordList[i], apex)

			// wait for free worker thread
			queue <- domainName
			// Add an item to the WaitGroup
			childrenWait.Add(1)
			go func() {
				// Defer removing ourselves from the WaitGroup once we're complete
				defer childrenWait.Done()

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
					}

					// If we're not yet at the minimum depth, we need to recurse even if this didn't resolve
					if currentDepth < minDepth {
						childDone := resolveList(queue, domainName, checkWildcard(domainName), currentDepth+1)
						// wait for child to finish
						<-childDone
					}
					return
				}

				// Check if it's a wildcard
				if len(wildcard) > 0 {
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
				childDone := resolveList(queue, domainName, checkWildcard(domainName), currentDepth+1)
				// wait for child to finish
				<-childDone
			}()
		}
		// Wait for all children to complete
		childrenWait.Wait()

		// Signal we're done
		doneChan <- true
	}()
	return doneChan
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

func checkZoneTransfer(domain string) (success bool) {
	// Bypass this check if we're configured to not attempt zone transfers
	if !zonetransfer {
		return false
	}
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
