What's Friction Ridge?
======================


        o   ^__^
         o  (oO)\_______
            (__)\       )\/\
                ||----W |
                ||     ||

  It's a simple Python script...
  * Empowered by python-libnmap
  * Uses Nmap XML outputs
  * Remotely detect the Operational System based on a custom score system techniques
  * Try to goes beyond Nmap fingerprint engine

  
Installing:
===========

	# pip install python-libnmap pyOpenSSL
	# git clone https://github.com/ulissescastro/friction-ridge.git


Usage:
======

	usage: friction-ridge.py [-h] [-f FILE] [-d DIRECTORY] [-o OUTPUT] [-v VERBOSE]

	Nmap XML outputs + Fingerprint Techniques = Guess system that show the most probable remote Operational System.

	optional arguments:
  	-h, --help    show this help message and exit
  	-d DIRECTORY  Recursively look for nmap XML files inside a directory.
  	-f FILE       Nmap XML output file.
  	-o OUTPUT     consolidated CSV output file.
  	-v, --verbose more detailed mode.


Example:
========
	
	tbd.

	* tbd:
  

Author:
=======

  Ulisses Castro | uss.thebug[@]gmail.com

