# glugger

A really faster DNS bruteforcer.
It lacks features.

## thanks
Thanks to [subbrute](https://github.com/TheRook/subbrute) for the wordlist

## todo
* investigate benifit of having multiple resolvers rather than relying on the system resolver
* investigate whether to lookup against domain nameservers directly

## performance
Quick benchmarking shows the following difference in resolvers as at commit 8534b8728c7dcf02c5003945f84d613392785da5, with a 2000 thread test:
*go*:
```
ss23@crisp ~/glugger $ time GODEBUG=netdns=go ./main -domain [*] -threads 2000
real    0m48.919s
user    0m5.793s
sys     0m2.927s
```

*cgo*:
```
ss23@crisp ~/glugger $ time GODEBUG=netdns=cgo ./main -domain [*] -threads 2000

real    2m27.202s
user    0m3.627s
sys     0m4.527s
```
