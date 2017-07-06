#!/usr/bin/python
# threatintel.py - Prints the threats intel for a certain IOCs taken as an argument
# Author: Abdoul Wahab Guisset 

import ConfigParser
import time
import requests
import io
import json, urllib, urllib2
import sys
import os
import thread

from common import is_url
from common import is_ip
from common import http_checker

#TYPE 
JSON = '?json'

# URL
BASE_URL = 'https://isc.sans.edu/api/'

def honeypot_parser():
	for i in sys.argv:
	    """ Ne pas oublie de mettre os.path.dirname(os.path....) pour ne pas mettre le chemin en dur"""
	    with open(os.path.abspath('honeypot.json'), 'r') as f:
	        # Loop on json file line by line
	        for line in f: 
	            threat_intel = {}
	            data = json.loads(line) # load it as Python dict
	            threat_intel = json.loads(data.get('payload')).get('victimIP')

	            # Case where the value in dict is equal to argument
	            if threat_intel == i:
	            	# Truncate the date
	            	somedate = str(data['timestamp']['$date'])
	            	date,rest = somedate.split('T')
	            	
	            	# Print useful information
	            	print('')
	            	print('Information for Victim IP {}'.format(json.loads(data.get('payload')).get('victimIP')))
	            	print('Attacker IP {}'.format(json.loads(data.get('payload')).get('attackerIP')))
	            	print('Connection Type: {}'.format(json.loads(data.get('payload')).get('connectionType')))
	            	print('Source: honeypot')
	            	print('Time stamp {}'.format(date))
	            	    

	               
def ip(ip_address):
    """Returns a summary of the information our database holds for a
    particular IP address.
    Input:  - a valid IP adress 
    		
    Output: - Count (total number of packets blocked from this IP)
    		- Attacks and Targets (number of unique destination IP addresses for these packets)
    """
    url = ''.join([BASE_URL,'ip/{address}'.format(address=ip_address),JSON])

    # HTTP get request
    response = requests.get(url)

    # Check HTTP code
    http_checker(response)
    data = response.json()
    

    	# Check if there is information to display
    if  data.get('count'):
    	# Print useful information
    	print
    	print('Information for Victim IP {}'.format(ip_address))
    	print('Number of packets blocked from this IP: {}'.format(data.get('count')))
    	print('Number of attacks {}:'.format(data.get('attacks')))
    	print('Source: Internet Storm Center (ISC)')
    	print('Time stamp {}'.format(data.get('maxdate')))
    else:
    	pass
  		
def port(port_number):
	""" Summary information about a particular port
		Input: Port Number
		Output: Records, targets,sources
	"""
	url = ''.join([BASE_URL,'port/{port}'.format(port=port_number),JSON])

	# HTTP get request
	response = requests.get(url)

	# Check HTTP code
	http_checker(response)
	data = response.json()

		# Check if there is information to display
	if  data.get('records'):
		# Print useful information
		print('')
		print('Information for Victim Port {}'.format(data.get('number')))
		print('Records: {}'.format(data.get('records')))
		print('Targets: {}:'.format(data.get('targets')))
		print('Source: Internet Storm Center (ISC)')
		print('Time stamp {}'.format(data.get('date')))
	else:
		pass


def virus_total_ip(argument):
	""" retrieve a report on a given IP address from virustotal """
	
	virus_total_url = 'http://www.virustotal.com/vtapi/v2/ip-address/report'

	# Get API_KEY from config.init
	config = ConfigParser.RawConfigParser(allow_no_value=True)
	config.readfp(open('api_keys.ini'))
	
	
	
	parameters = {'ip':str(argument),'apikey':config.get("API","virus_total")}
	url = virus_total_url 
	

	# Pagination
	while url:
	    response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters)))
	    
	    if response.getcode() == 204:
	        print('Rate limited! Please wait.')
	        time.sleep(int(response.headers['retry-after']))
	        continue

	    # HTTP CHECKER
	    if response.getcode() != 200:
	        print('Error with status code {}'.format(response.getcode()))
	        exit()

	    # Case where we don't have the required privelege 
	    if response.getcode() == 403:
	        print('HTTP Error 403 Forbidden {}'.format(response.getcode()))
	        exit()

	    # No information regarding the IP address under consideration
	    if response.getcode() == 0:
	    	print('No information regarding the IP address requested !')
	    	continue
	    response= response.read()
	    response_dict = json.loads(response)
	    
	    
	    return response_dict

def virus_total_url(argument):
	"""retrieve a scan report on a given URL """
	virus_total_url =  "https://www.virustotal.com/vtapi/v2/url/report"


	# Get API_KEY from config.init
	config = ConfigParser.RawConfigParser(allow_no_value=True)
	config.readfp(open('api_keys.ini'))
	
	parameters = {"resource": str(argument),"apikey":config.get("API","virus_total")}
	
	url = virus_total_url
	

	# Pagination
	while url:
		
	    data = urllib.urlencode(parameters)
	    req = urllib2.Request(url,data)
	    response = urllib2.urlopen(req)
	    if response.getcode() == 204:
	        print('Rate limited! Please wait.')
	        time.sleep(int(response.headers['retry-after']))
	        continue

	    # HTTP CHECKER
	    if response.getcode() != 200:
	        print('Error with status code {}'.format(response.getcode()))
	        exit()

	    # Case where we don't have the required privelege 
	    if response.getcode() == 403:
	        print('HTTP Error 403 Forbidden {}'.format(response.getcode()))
	        exit()

	    # No information regarding the IP address under consideration
	    if response.getcode() == 0:
	    	print('No information regarding the IP address requested !')
	    	continue
	    response= response.read()
	    
	    
	    
	    return response

def virus_total_parser(argument):
	""" Parse the data from virustotal """
	
	
	if is_ip(argument):
		data = virus_total_ip(argument)
		threat_intel = data.get('resolutions')
		
		for info in threat_intel:
			
			print('')

			# Test on ip adress
			print('Information for Victim IP {}'.format(argument))
			print('hostname {}'.format(info['hostname']))
			print('Connection Type: HTTP GET')
			print('Source: virustotal')
			print('Time stamp {}'.format(info['last_resolved']))
	
	elif is_url(argument):
		
		data =virus_total_url(argument)
		data = json.loads(data)
		threat_intel = data.get('scans')

		print('')

		# Test on ip adress
		print('Information for Url {}'.format(data.get('url')))
		for user in threat_intel:
			print('\t{} is a {}'.format(user,threat_intel[user]['result']))

		print('Connection Type: HTTP POST')
		print('Source: virustotal')
		print('Scan date {}'.format(data.get('scan_date')))

		print('')

def iocs_type(command_line_input):
	"""Determine which kind of IOCs we deal with and call the right function
	   Input:  - The command line input
	   Output: - Dictionnary containing all the types
	"""
	iocs_type = {}
	for argument in sys.argv:
		
		
		if is_ip(argument):
			iocs_type['IP_ADDRESS'] = 'IP'
			ip(argument)
			honeypot_parser()

		if is_url(argument):
	
			iocs_type['URL_LINK'] = 'URL'			
			virus_total_parser(argument)
			
		
def main():
	""" Execute the script """
	# Check correct number of argument 
	if len(sys.argv) <2:
		print "Usage : threatintel.py [IOCs]"
		sys.exit()
	else:
		# Slicing
		sys.argv = sys.argv[1:]

		iocs_type(sys.argv)



if __name__ == "__main__":
	main()


   