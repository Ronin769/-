# MyRSA.py
## Introduction ##

- This program is based on information in the information box to encrypt and decrypt, encryption and decryption operations and read the file has nothing to do.

- The reset operation will delete the exc, pyc, pem files in the current folder.

- This program can be used to transfer information between users

- Inadequacies: Can't resist man-in-the-middle attacks on public key information.

- Thanks to AI Sweigart

	[Hacking Secret Ciphers with Python](http://inventwithpython.com/hacking)


## Environment ##

	Windows
	Python 3.6
	wxPython 4.0.1

## INSTALL ##

[Python Download](https://www.python.org/)

	pip3 install wxpython 
	pip3 install pyinstaller

or

	pip install wxpython 
	pip install pyinstaller


## Generate executable ##

	pyinstaller -F -w -i icon.ico MyRSA.py

