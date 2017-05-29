#!/usr/bin/env python
#
# Download all the data on Shodan for a list of IP addresses.
# If the 3rd argument is provided ("[with history]") then the script will also download
# historical information.
#
# Example:
# python shodan-ip-download.py ips.txt results.json.gz true

from shodan import Shodan
from shodan.helpers import open_file, write_banner
from shodan.cli.helpers import get_api_key
from sys import argv, exit

# Input validation
if len(argv) < 3 or len(argv) > 4:
	print('Usage: {} <IPs filename> <output filename> [with history]'.format(argv[0]))
	exit(1)

input_filename = argv[1]
output_filename = argv[2]

# Whether or not to look up historical information for the IPs
use_history = False
if len(argv) == 4:
	use_history = True

# Must have initialized the CLI before running this script
key = get_api_key()

# Create the API connection
api = Shodan(key)

# Create the output file
fout = open_file(output_filename, 'w')

# Open the file containing the list of IPs
with open(input_filename, 'r') as fin:
	# Loop over all the IPs in the file
	for line in fin:
		ip = line.strip() # Remove any trailing whitespace/ newlines

		# Wrap the API calls to nicely skip IPs which don't have data
		try:
			print('Processing: {}'.format(ip))
			info = api.host(ip, history=use_history)
			
			# All the banners are stored in the "data" property
			for banner in info['data']:
				write_banner(fout, banner)
		except:
			pass # No data