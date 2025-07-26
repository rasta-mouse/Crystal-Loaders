# Postex Loader

This loader is used with Beacon's fork & run commands that utilise a postex DLL.

It assumes that `post-ex.smart-inject` is enabled to receive pointers to
GetModuleHandleA and GetProcAddress from the parent Beacon.  The loader
uses these to resolve APIs required to load the DLL, rather than walking
the export address table.

The loader also passes RDATA_SECTION information to the postex DLL, as
some long-running jobs can obfuscate their .rdata section while waiting.

The postex DLL is masked with a random XOR key and unmasked at runtime.
