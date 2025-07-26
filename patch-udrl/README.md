# Patch Loader

This loader is used when the BEACON_RDLL_GENERATE_LOCAL hook is called,
i.e. when Beacon commands like `spawn` are used.

It's practically identical to the normal BEACON_RDLL_GENERATE hook but it receives
function pointers to GetModuleHandleA and GetProcAddress from the parent Beacon.

These are patched into the loader so that it doesn't have to walk the EAT to find APIs.
This makes the loader more OPSEC-safe against mechanisms that detect this behaviour.

## Notes

1. `stage.smartinject` must be `true` in Malleable C2.

2. `stage.smartinject` is not yet supported for prepended loaders, so this loader
    is useless until stomped loaders are deprecated from CS.

3. Also means this one is largely untested.