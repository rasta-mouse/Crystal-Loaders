# BUD Loader

This loader is used when the BEACON_RDLL_GENERATE hook is called,
i.e. when a new Beacon payload is generated.

This loader passes Beacon's memory allocation information to Beacon
via Beacon User Data (BUD).  It also uses a port of [LibGate](https://github.com/rasta-mouse/LibGate) to
resolve and pass syscall information to Beacon.

Beacon is masked with a random XOR key and unmasked at runtime.

## Notes

1. It's expected that Beacon will free the loader (`stage.cleanup`).
