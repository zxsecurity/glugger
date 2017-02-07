package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"reflect"
	"sync"
)

var wordList []string

// This is a cache of the mapping of domains to their wildcard addresses, e.g.
// *.example.com is stored as ["example.com"] = [127.0.0.1]
var wildcardRegistry map[string][]string
var wildcardRegistryMutex sync.RWMutex

func main() {
	// Parse cmdline
	flag_domain := flag.String("domain", "", "The target domain")
	flag_wordlist := flag.String("wordlist", "wordlist.txt", "Path to the wordlist")
	flag_threads := flag.Int("threads", 20, "Number of concurrent threads")

	flag.Parse()

	if *flag_domain == "" {
		fmt.Fprint(os.Stderr, "You must specify a domain\r\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	file, err := os.Open(*flag_wordlist)
	if err != nil {
		panic(err)
	}

	// Make our new wildcard map
	wildcardRegistry = make(map[string][]string)
	// Check for wildcard record(s) before starting
	wildcardDetected := checkWildcard(*flag_domain)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordList = append(wordList, scanner.Text())
	}

	queue := make(chan string, *flag_threads)
	done := resolveList(queue, *flag_domain, wildcardDetected)
	<-done
}

func resolveList(queue chan string, apex string, wildcardDetected bool) chan bool {
	doneChan := make(chan bool)
	go func() {
		for i := range wordList {
			domainName := fmt.Sprintf("%s.%s", wordList[i], apex)

			// wait for free worker thread
			queue <- domainName
			go func() {
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
					return
				}

				// Check if it's a wildcard
				if wildcardDetected {
					// Read lock the mutex
					wildcardRegistryMutex.RLock()
					if reflect.DeepEqual(ips, wildcardRegistry[apex]) {
						// Not a real finding -- see note about the bug at wildcard definition
						wildcardRegistryMutex.RUnlock()
						return
					}
					wildcardRegistryMutex.RUnlock()
				}

				// we found a non-wildcard sub domain, recurse
				fmt.Printf("%s %v\n", domainName, ips)
				childDone := resolveList(queue, domainName, checkWildcard(domainName))
				// wait for child to finish
				<-childDone
			}()
		}
		doneChan <- true
	}()
	return doneChan
}

func checkWildcard(domain string) bool {
	// Check for wildcard record(s)
	randomString := randomString(10)
	wildcard, _ := net.LookupHost(randomString + "." + domain)
	if len(wildcard) > 0 {
		fmt.Fprintf(os.Stderr, "Detected wildcard record: %s\r\n", domain)
		// Lock for writing
		wildcardRegistryMutex.Lock()
		wildcardRegistry[domain] = wildcard
		wildcardRegistryMutex.Unlock()
		return true
	}
	return false
}

func randomString(length int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
