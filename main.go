package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

var mux sync.Mutex
var doer int

func main() {
	// A channel for domains still to be processed
	// Using a buffered channel here is a requirement of how we've done our multithreading
	toProcess := make(chan string, 100)

	// A mutex for locking the counter of active threads
	mux = sync.Mutex{}

	// Initialize our doer
	// Warning: There is a race condition here - if addToChannel doesn't add items to the list faster than
	// the threads can process them, eventually doer will be 0, and the threads will exit prematurely.
	// Lets hope people have fast CPUs and slow internet!
	doer = 1

	wordlist, domain, threads, _ := setup()

	// Waitgroup for all our threads
	processorGroup := new(sync.WaitGroup)
	processorGroup.Add(threads)

	// Do our threads
	for i := 0; i < threads; i++ {
		go process(toProcess, wordlist, processorGroup)
	}

	addToChannel(wordlist, domain, toProcess) // Do this in the background
	// Remove ourselves from the list of doers
	mux.Lock()
	doer -= 1
	mux.Unlock()

	// Wait to finish
	processorGroup.Wait()
}

func setup() (wordlist []string, domain string, threads int, err error) {
	// Parse cmdline
	flag_domain := flag.String("domain", "", "The target domain")
	wordlistFilename := flag.String("wordlist", "wordlist.txt", "Path to the wordlist")
	flag_threads := flag.Int("threads", 20, "Number of concurrent threads")

	flag.Parse()

	if *flag_domain == "" {
		fmt.Println("You must specify a domain")
	}

	// Open wordlist
	wordlist = []string{}
	file, err := os.Open(*wordlistFilename)
	if err != nil {
		panic(err)
	}
	// Parse in wordlist
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		wordlist = append(wordlist, scanner.Text())
	}
	return wordlist, *flag_domain, *flag_threads, nil
}

func addToChannel(wordlist []string, suffix string, toProcess chan<- string) {
	// loop over wordlist, and for each, check DNS
	for _, word := range wordlist {
		toProcess <- word + "." + suffix
	}
}

func process(toProcess chan string, wordlist []string, processorGroup *sync.WaitGroup) {
StartLock:
	// Mark ourselves as active
	mux.Lock()
	doer += 1
	mux.Unlock()

	for len(toProcess) > 0 {
		// Non-blocking recieve
		select {
		case word := <-toProcess:
			_, err := net.LookupHost(word)
			if err != nil {
				break
			}
			fmt.Println(word)
			// Add every item to the queue
			addToChannel(wordlist, word, toProcess)
		default:
		}
	}

	// Mark outselves as inactive
	mux.Lock()
	doer -= 1
	mux.Unlock()

	// Sleep to allow all threads to finish if nessecary
	time.Sleep(10 * time.Millisecond)

	mux.Lock()
	if doer == 0 && len(toProcess) == 0 {
		processorGroup.Done()
		mux.Unlock()
		return
	}
	mux.Unlock()
	goto StartLock
}
