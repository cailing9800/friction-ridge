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

	usage: friction-ridge.py [-h] (-f FILE | -d DIR) [--output OUTPUT] [--debug]

	optional arguments:
	  -h, --help            show this help message and exit
	  -f FILE, --file FILE  load a nmap XML file
	  -d DIR, --dir DIR     directory to recursively search for nmap XML files
	  --output OUTPUT       output fingerprinted CSV file (default: recon.csv)
	  --debug               debug mode


TODO:
=======

    * Code clean up
    * Better info, error and debug messages
    * Improve detection algorithm


Author:
=======

  Ulisses Castro | uss.thebug[@]gmail.com

