# Loader

This loader is used when the BEACON_RDLL_GENERATE hook is called,
i.e. when a new Beacon payload is generated.

This loader also allocates memory for BOFs and the Sleepmask, and
passes the information to Beacon via Beacon User Data.

## todo

1. Resolve syscall information for Beacon as well.
