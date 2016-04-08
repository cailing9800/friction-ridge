
    .---.     _       .-.  _               .---.  _    .-.            
    : .--'   :_;     .' `.:_;              : .; ::_;   : :            
    : `;.--. .-. .--.`. .'.-. .--. ,-.,-.  :   .'.-. .-' : .--.  .--. 
    : : : ..': :'  ..': : : :' .; :: ,. :  : :.`.: :' .; :' .; :' '_.'
    :_; :_;  :_;`.__.':_; :_;`.__.':_;:_;  :_;:_;:_;`.__.'`._. ;`.__.'
                                                       .-. :      
                                                       `._.'      

Nmap XML outputs + Fingerprint Techniques = Guess system that show the most probable remote Operational System.


What's Friction Ridge?
===============

	It's a simple Python script empowered by python-libnmap that uses Nmap XML outputs to try remotely detect the Operational System based on a custom score system techniques that goes beyond Nmap fingerprint engine.


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

