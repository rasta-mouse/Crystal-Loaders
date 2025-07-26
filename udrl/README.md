# BUD Loader

This loader is used when the BEACON_RDLL_GENERATE hook is called,
i.e. when a new Beacon payload is generated.

This loader allocates memory for BOFs and the Sleepmask, and
passes the information to Beacon via Beacon User Data.  It also uses
a port of [RecycledGate](https://github.com/thefLink/RecycledGate) to resolve and pass syscall information.

Beacon is masked with a random XOR key and unmasked at runtime.

## Notes

1. It's expected that Beacon will free the loader (`stage.cleanup`).