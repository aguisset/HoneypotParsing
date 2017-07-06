---------------- PYTHON CHALLENGE -----------------

- Name: threadintel.py 
- Submodule: common.py
- Other: api_key.ini

----------------   Description    -------------------
The goal of this exercise is to accept Indicators Of Compromise as arguments to the program and look up all information related to the IOCsin the honeypot provided as well as some public APIs.

There is one submodule: common.py which contains some function used in the threatintel.py
The api_keys.ini contains each api keys.

----------------   Instructions    -------------------
This code was tested on Python 2.7.10 

- To run the code, extract the .zip file in a folder.
- Launch the terminal application and install the module "requests" by running this sample command: pip install requests
- Then run: python threatintel.py [IOCs]
	Example: python threatintel.py 192.161.23.45 192.161.34.52

	Please note that each IOCs are split by space.




Author: Abdoul Wahab Guisset 
