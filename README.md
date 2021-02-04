# Famine
x64 Assembly linux virus

## Infection method
Data segment

original:

	[text]
	[data]

parasite:

	[text]
	[data]
	[parasite]

## Description
* Self replicating code in x64 linux binaries, will infect all compatible binaries (only once) in a defined path.  
* Since i dont want the virus to be too virulent for this project, i only search for binaries in the current folder.  
* Of course the payload is not malicious and will only print a mark on stdout.  

## Demo
![Virus demo](demo.gif)
