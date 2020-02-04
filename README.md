# Read EOF Data from Portable Executable File (x86 / x64)

![EOF Reader](https://i.imgur.com/XaZfB5v.jpg "EOF Reader")

This program detects the presence of suspicious EOF data from any valid PE File.

Malware often uses append to the end of file :

* C2 Configurations
* Other malicious applications / plugins
* Payloads

This program calculates the real expected size for a PE File through the PE Header and compares that size with the size of the file on disk. 

If the size on disk is greater than the size described by the PE Header we are likely facing an infected file. 

After detecting the presence of EOF, it dumps its content in content (Hex Editor Style) then offer you to save it raw content to disk.

The code is probably not the most optimised and I'm open to any suggestions or fixes. I come from a very long background in Pascal / Delphi for Win programming 
I'm not yet as expert in C++ than Pascal / Delphi. 

Coded & Compiled with success on Visual Studio 2019.

# Special Thanks goes to 

* ikalnytskyi for termcolor lib (https://github.com/ikalnytskyi/termcolor)
