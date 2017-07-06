#!/usr/bin/python
# common.py - Common function or variable used by all the scripts
# Author: Abdoul Wahab Guisset

import unittest

#TYPE 
JSON = '?json'

# URL
BASE_URL = 'https://isc.sans.edu/api/'

# Test function
def is_url(s):
	"""Validate url.
	   Input:  - Some string.
	   Output: - Boolean (True or False).
	"""
	if "http://" or "https://" or "www." in s:
		return True
	else:
		return False

def is_ip(s):
	""" Validate ip address.
		Input:  - s (command line argument)
		Output: - Boolean (True or False)
	""" 
	a = s.split('.')
		
	# Ip address must be on 4 bytes
	if len(a) != 4:
	    return False

	# Check number     
	for x in a:
	    if not x.isdigit():
	        return False
	    i = int(x)
	    if i < 0 or i > 255:
	        return False
	return True

def http_checker(response):
	"""Check if HTTP code is other than 200 (failure) """

	if response.status_code != 200:
	    print('Status:', response.status_code, 'Problem with the request. Exiting.')
	    exit()