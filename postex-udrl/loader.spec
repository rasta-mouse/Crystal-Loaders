name     "Beacon Postex Loader"
describe "PIC loader for Cobalt Strike's postex DLLs"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +gofirst +optimize +disco
		dfr "resolve" "strings"
		patch "pGetModuleHandle" $GMH
		patch "pGetProcAddress"  $GPA
		mergelib "../libtcg.x64.zip"

	generate $KEY 128

	push $DLL
		xor $KEY
		preplen
		link "dll"

	push $KEY
		preplen
		link "key"
	
	export