##### This script checks for Clickjacking, OPTIONS Method, Host header injection, Reflective XSS and CORS in a host.
##### Author: Mystog3n
##### Version: 1.0

#/usr/bin/python

import requests
import argparse
import sys


# Global Variables
vulns = {}
req_headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'}


# To parse the arguments
def getOptions(args=sys.argv[1:]) :

	parser = argparse.ArgumentParser(description="Bug Bounty Test")
	parser.add_argument("-d", "--domain", help = "enter host to scan", required = True, nargs = 1)
	parser.add_argument("-a", "--all",default = False, help = "Search Everything", action='store_true')
	parser.add_argument("--click",default = False, help = "Search Clickjacking", action='store_true')
	parser.add_argument("--cors",default = False, help = "Search CORS", action='store_true')
	parser.add_argument("--options",default = False, help = "Search OPTIONS Method", action='store_true')
	parser.add_argument("--xss",default = False, help = "Search Reflective XSS", action='store_true')
	parser.add_argument("--host",default = False, help = "Search host header injection", action='store_true')
	

	options = parser.parse_args(args)

	return options


# To check for vulnerabilities
def check_vuln(url) :
	response = requests.get(url, headers = req_headers)
	headers = response.headers

	if scanClick or scanAll:
		click(headers)
	if scanCORS or scanAll:
		cors(headers)
	if scanOption or scanAll:
		options(url)
	if scanXSS or scanAll:
		ref_xss(url)
	if scanHost or scanAll:
		host_header(url)


############ Vulnerabilities Begin ###############

# Test for clickjacking
def click(headers) :
	try :
		headers["X-Frame-Options"]
	except KeyError :
		vulns["Clickjacking"] = True


# Test for CORS
def cors(headers) :
	try :
		if headers["Access-Control-Allow-Origin"] == "*" :
			vulns["CORS Poorly Implemented"] = True
		else :
			vulns["CORS Exploitable"] = True
	except KeyError :
		pass


# Test for OPTIONS Method
def options(url) :
	response = requests.request(method = "OPTIONS", url = url, headers = req_headers)
	try: 
		response.headers["Allow"]
		vulns["Options Method Enabled"] = True
	except KeyError :
		try: 
			response.headers["Access-Control-Allow-Methods"]
			vulns["Options Method Enabled"] = True
		except KeyError :
			pass


# To check for Reflective XSS
def ref_xss(url) :
	response = requests.get(url = url + "/?abc=<script>alert(1)</script>", headers = req_headers)
	if "<script>alert(1)</script>" in response.text :
		vulns["Reflective XSS"] = True


# Test for host header injcetion
def host_header (url) :
	req_headers["host"] = "batman.com"
	response = requests.get(url = url, headers = req_headers, allow_redirects = False)
	if "batman.com" in response.text :
		vulns["Host Header Injection"] = True


############ Vulnerabilities End ###############


# To display the vulnerabilities found
def disp_vuln () :

	if True in vulns.values() :
		print("Host: " + host)

		for key in vulns.keys() :
			if vulns[key] :
				print("\t" + host + " is vulnerable to " + key + "!")

		print("Report at " + host + "\n")


args = getOptions()	# Gets command line options
host = args.domain[0]

scanAll = args.all
scanHost = args.host
scanOption = args.options
scanClick = args.click
scanXSS = args.xss
scanCORS = args.cors

if not (scanAll or scanClick or scanHost or scanOption or scanXSS):
	print("Select atleast 1 scan option")
	exit(2)

try :
    x = requests.get("https://www.google.com")	# Check if google.com can be connected to check interne connection
except requests.exceptions.ConnectionError :
    print("Network is down")

host = host.replace("https://","").replace("http://","").rsplit('/')[0]

url = "https://" + host	# Prepend protocol to the host name

try :
	check_vuln(url)
	disp_vuln()

except requests.exceptions.ConnectionError :
	pass

except KeyboardInterrupt :
	print("User interrupted the execution!")
	exit(130)
