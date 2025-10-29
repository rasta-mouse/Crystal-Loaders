name     "Beacon BUD Loader"
describe "PIC loader to pass memory allocation information via Beacon User Data"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +gofirst +optimize +disco
		dfr "resolve" "ror13"
		mergelib "../libgate.x64.zip"
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