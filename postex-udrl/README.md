# Postex UDRL

This loader is used with Beacon's fork & run commands that utilise a post-ex DLL.

It assumes `post-ex.smart-inject` is set to true in Malleable C2 to receive pointers to
GetModuleHandleA and GetProcAddress.  It will use these when processing imports before
resorting to LoadLibraryA.

This loader also passes RDATA_SECTION information to the post-ex DLL.