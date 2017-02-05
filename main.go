package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"reflect"
)

var wordList []string

// TODO: A bug exists in that we're only doing wildcard detection on the root domain
// If a subdomain contains a wildcard, it will not be detected during recursive scanning
var wildcard []string
var wildcardDetected bool

func main() {
	// Parse cmdline
	flag_domain := flag.String("domain", "", "The target domain")
	flag_wordlist := flag.String("wordlist", "wordlist.txt", "Path to the wordlist")
	flag_threads := flag.Int("threads", 20, "Number of concurrent threads")

	flag.Parse()

	if *flag_domain == "" {
		fmt.Println("You must specify a domain")
		flag.PrintDefaults()
		os.Exit(1)
	}
	file, err := os.Open(*flag_wordlist)
	if err != nil {
		panic(err)
	}

	// Check for wildcard record(s)
	randomString := randomString(10)
	wildcard, _ = net.LookupHost(randomString + "." + *flag_domain)
	if len(wildcard) > 0 {
		fmt.Println("Detected wildcard record")
		wildcardDetected = true
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordList = append(wordList, scanner.Text())
	}

	queue := make(chan string, *flag_threads)
	done := resolveList(queue, *flag_domain)
	<-done
}

func resolveList(queue chan string, apex string) chan bool {
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
					return
				}

				// Check if it's a wildcard
				if wildcardDetected && reflect.DeepEqual(ips, wildcard) {
					// Not a real finding -- see note about the bug at wildcard definition
					return
				}

				// we found a non-wildcard sub domain, recurse
				fmt.Printf("%s %v\n", domainName, ips)
				childDone := resolveList(queue, domainName)
				// wait for child to finish
				<-childDone
			}()
		}
		doneChan <- true
	}()
	return doneChan
}

func randomString(length int) string {
	letterRunes := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
