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
)

var wordList []string

var outputType string

// Whether this is the first line of output to print
var outputFirst bool

func main() {
	// Parse cmdline
	flag_domain := flag.String("domain", "", "The target domain")
	flag_wordlist := flag.String("wordlist", "wordlist.txt", "Path to the wordlist")
	flag_threads := flag.Int("threads", 20, "Number of concurrent threads")
	flag_output := flag.String("output", "csv", "Output type (csv, json)")

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
	default:
		fmt.Fprintf(os.Stderr, "Invalid output format specified\r\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	file, err := os.Open(*flag_wordlist)
	if err != nil {
		panic(err)
	}

	// Check for wildcard record(s) before starting
	wildcard := checkWildcard(*flag_domain)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordList = append(wordList, scanner.Text())
	}

	queue := make(chan string, *flag_threads)
	done := resolveList(queue, *flag_domain, wildcard)
	<-done
}

func resolveList(queue chan string, apex string, wildcard []string) chan bool {
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
					return
				}

				// Check if it's a wildcard
				if len(wildcard) > 0 {
					if reflect.DeepEqual(ips, wildcard) {
						return
					}
				}

				// we found a non-wildcard sub domain, recurse
				outputResult(domainName, ips)
				childDone := resolveList(queue, domainName, checkWildcard(domainName))
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

func outputResult(domain string, ips []string) {
	switch outputType {
	case "json":
		if outputFirst {
			fmt.Printf("{\r\n")
			outputFirst = false
		} else {
			fmt.Printf(",\r\n")
		}
		fmt.Printf("{\"%s\": {\"%s\"}}", domain, strings.Join(ips, "\",\""))
	case "csv":
		fmt.Printf("%s,%s\r\n", domain, strings.Join(ips, ","))
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
