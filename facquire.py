#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Facquire v.0.1 - A forensically-sound tool to acquire a page of Facebook
#########################################################################
#                                                                     	#
# Developed by Mattia Reggiani, info@mattiareggiani.com               	#
#                                                                     	#
# This program is free software: you can redistribute it and/or modify	#
# it under the terms of the GNU General Public License as published by	#
# the Free Software Foundation, either version 3 of the License, or	#
# (at your option) any later version.					#
#									#
# This program is distributed in the hope that it will be useful,      	#
# but WITHOUT ANY WARRANTY; without even the implied warranty of       	#
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        	#
# GNU General Public License for more details.                         	#
#                                                                      	#
# You should have received a copy of the GNU General Public License    	#
# along with this program. If not, see <http://www.gnu.org/licenses/>  	#
#                                                                      	#
# Released under the GNU Affero General Public License                 	#
# (https://www.gnu.org/licenses/agpl-3.0.html)                         	#
#########################################################################
WARNING: the potential of this program is limited by the API limitations provided by Facebook
	For further information, please visit https://developers.facebook.com/docs/graph-api/advanced/rate-limiting
	
Usage examples:
	Get fingerprint (MD5 and SHA1) of page
	./facquire.py -f WhoIsMrRobot
	
	Get basic info of page
	./facquire.py -i WhoIsMrRobot
	
	Get Timeline of page
	./facquire.py -t WhoIsMrRobot
	
"""

import httplib, json, sys, urllib2, urlparse, requests, string, os, argparse, hashlib
from requests.auth import HTTPProxyAuth
from datetime import datetime

__version__='v0.1'
__description__='''\
  ___________________________________________________________
  
  Facquire - A forensically-sound tool to acquire a page of Facebook
  Author: Mattia Reggiani (info@mattiareggiani.com)
  Github: https://github.com/mattiareggiani/facquire
  ___________________________________________________________
'''
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# Data
host = 'graph.facebook.com'
debug = True
BASE = "/v2.5"
hdr = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:14.0) Gecko/20100101 Firefox/14.0.1'}
LONG_TERM_TOKEN = "INSERT_YOUR_TOKEN_HERE"
##

def getInfo(page):
	f = open(os.getcwd() + '/report_' + page + '.txt', 'a')
	f.write("\nReport: " + str(datetime.now()) + " - " + page)
	conn = httplib.HTTPSConnection(host)
	printColour("\n[*] ", BLUE)
	print "Getting information..."
	printColour("\n\n[>] ", CYAN)
	print "Basic info of: " + page
	f.write("\nBasic info of: " + page)
	r = BASE + "/" + page + "?fields=id&access_token=" + LONG_TERM_TOKEN
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	printColour("\n[+] ", GREEN)
	print "ID: " + JDict["id"] 
	f.write("\nID: " + JDict["id"] )

	r = BASE + "/" + page + "?fields=name&access_token=" + LONG_TERM_TOKEN
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	printColour("\n[+] ", GREEN)
	print "Name: " + JDict["name"] 	
	f.write("\nName: " + JDict["name"] )
	
	r = BASE + "/" + page + "?fields=fan_count&access_token=" + LONG_TERM_TOKEN
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	printColour("\n[+] ", GREEN)
	print "Likes: " + str(JDict["fan_count"])
	f.write("\nLikes: " + str(JDict["fan_count"]))
	
	r = BASE + "/" + page + "?fields=about&access_token=" + LONG_TERM_TOKEN
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	printColour("\n[+] ", GREEN)
	print "About: " + JDict["about"].encode('utf-8','replace')
	f.write("\nAbout: " + JDict["about"].encode('utf-8','replace'))

	r = BASE + "/" + page + "?fields=website&access_token=" + LONG_TERM_TOKEN
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	printColour("\n[+] ", GREEN)
	print "Website: " + JDict["website"].encode('utf-8','replace')
	f.write("\nWebsite: " + JDict["website"].encode('utf-8','replace'))
	print "\n"
	f.close()

def getEvents(page):
	f = open(os.getcwd() + '/report_' + page + '.txt', 'a')
	f.write("\nReport: " + str(datetime.now()) + " - " + page)
	conn = httplib.HTTPSConnection(host)
	printColour("\n[*] ", BLUE)
	print "Getting information..."
	printColour("\n\n[>] ", CYAN)
	print "Events of: " + page
	f.write("\nEvents of: " + page)
	r = BASE + "/" + page + "?fields=events&access_token=" + LONG_TERM_TOKEN
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	for e in JDict["events"]["data"]:
		print "\n"
		printColour("\n[+] ", GREEN)
		print "Name: " + e["name"].encode('utf-8','replace')
		f.write("\nName: " + e["name"].encode('utf-8','replace'))
		if "start_time" in e:
			printColour("\n[+] ", GREEN)
			print "Start: " + e["start_time"]
			f.write("\nStart: " + e["start_time"])
		else:
			printColour("\n[-] ", BLUE)
			print "Start: N/A"
			f.write("\nStart: N/A")
		if "end_time" in e:
			printColour("\n[+] ", GREEN)
			print "End: " + e["end_time"]
			f.write("\nEnd: " + e["end_time"])
		else:
			printColour("\n[-] ", BLUE)
			print "End: N/A"
			f.write("\nEnd: N/A")
		if "description" in e:
			printColour("\n[+] ", GREEN)
			print "Description: " + e["description"].encode('utf-8','replace')
			f.write("\nDescription: " + e["description"].encode('utf-8','replace'))
		else:
			printColour("\n[-] ", BLUE)
			print "Description: N/A"
			f.write("\nDescription: N/A")
	conn.close()
	f.close()
	print "\n"

def getFingerprint(page):
	f = open(os.getcwd() + '/report_' + page + '.txt', 'a')
	f.write("\nReport: " + str(datetime.now()) + " - " + page)
	fingerprint = []	
	r = BASE + "/" + page + "?metadata=1&access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)
	if debug:
		printColour("\n[*] ", BLUE)
		print "Getting information...\n"
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	printColour("\n[>] ", CYAN)
	print "Fingerptint of: " + page
	f.write("\nFingerptint of: " + page)
	for i in JDict["metadata"]["fields"]:
		field = i["name"]
		r = BASE + "/" + page + "?fields=" + field + "&access_token=" + LONG_TERM_TOKEN
		conn = httplib.HTTPSConnection(host)
		conn.request("GET", "/" + r, headers=hdr)
		if debug:
			ris = conn.getresponse()
			data = ris.read()
			fingerprint.append(data)
	
	fingerprint.append(JDict["metadata"]["type"])

	r = BASE + "/" + page + "?fields=photos&access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	fingerprint.append(data)

	r = BASE + "/" + page + "?fields=videos&access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	fingerprint.append(data)
	
	r = BASE + "/" + page + "?fields=locations&access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	fingerprint.append(data)
	
	r = BASE + "/" + page + "?fields=albums&access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)
	ris = conn.getresponse()
	data = ris.read()
	fingerprint.append(data)
	
	conn.close()
	md5 = hashlib.md5(json.dumps(fingerprint)).hexdigest()
	printColour("\n[+] ", GREEN)
	print "MD5: " + md5 + "\n"
	sha1 = hashlib.sha1(json.dumps(fingerprint)).hexdigest()
	printColour("\n[+] ", GREEN)
	print "SHA1: " + sha1 + "\n"
	f.write("\nMD5: " + md5)
	f.write("\nSHA1: " + sha1)
	f.close()

def getFullInfo(page):
	f = open(os.getcwd() + '/report_' + page + '.txt', 'a')
	f.write("\nReport: " + str(datetime.now()) + " - " + page)
	fullInfo = []	
	r = BASE + "/" + page + "?metadata=1&access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)
	if debug:
		printColour("\n[*] ", BLUE)
		print "Getting information...\n"
	ris = conn.getresponse()
	data = ris.read()
	JDict = json.loads(data)
	tmpInfo = ""
	printColour("\n[>] ", CYAN)
	print "Full info of: " + page
	f.write("\nFull info of: " + page + "\n")
	for i in JDict["metadata"]["fields"]:
		field = i["name"]
		r = BASE + "/" + page + "?fields=" + field + "&access_token=" + LONG_TERM_TOKEN
		conn = httplib.HTTPSConnection(host)
		conn.request("GET", "/" + r, headers=hdr)
		if debug:
			ris = conn.getresponse()
			data = ris.read()
			tmpInfo = json.loads(data)
			if field in tmpInfo:
				if field != "ad_campaign" and field != "app_links" and field != "best_page" and field != "category_list" and field != "contact_address" and field != "context" and field != "cover" and field != "engagement" and field != "featured_video" and field != "location" and field != "owner_business" and field != "parent_page" and field != "parking" and field != "payment_options" and field != "restaurant_services" and field != "restaurant_specialties" and field != "start_info" and field != "checkins" and field != "voip_info":
					#Data structure not supported yet
					try:
						if tmpInfo[field] != True and tmpInfo[field] != False and isinstance( tmpInfo[field], int ) != True:
							printColour("\n[+] ", GREEN)
							print field
							print tmpInfo[field].encode('utf-8','replace')
							f.write("\n" + field)
							f.write("\n" + tmpInfo[field].encode('utf-8','replace') + "\n")
						else:
							printColour("\n[+] ", GREEN)
							print field
							print str(tmpInfo[field])
							f.write("\n" + field)
							f.write("\n" + str(tmpInfo[field]) + "\n")
					except Exception, e:
						printColour("\n[-] ", RED)
						print "Exception: " + str(e)
						f.write("\nException: " + str(e))
						continue
	conn.close()
	print "\n"
	f.close()

def getTimeline(page):
	f = open(os.getcwd() + '/report_' + page + '.txt', 'a')
	f.write("\nReport: " + str(datetime.now()) + " - " + page)
	r = BASE + "/" + page + "/posts?access_token=" + LONG_TERM_TOKEN
	rc = "/comments?access_token=" + LONG_TERM_TOKEN
	t = BASE + "/" + page + "/tagged?access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)

	if debug:
		printColour("\n[*] ", BLUE)
		print "Getting information...\n"
	ris = conn.getresponse()
	data = ris.read()

	JDict = json.loads(data)
	content = []
	printColour("\n[>] ", CYAN)
	print "Timeline of page: " + page
	f.write("\nTimeline of page: " + page)
	try:
		for i in JDict["data"]:
			id = i["id"]
			if "message" in i:
				post = i["message"].encode('utf-8','replace')
			else:
				post = ""
			if debug:
				printColour("\n[+] ", GREEN)
				print "ID: " + i["id"]
				printColour("[+] ", GREEN)
				print "Post: " + post
				f.write("\nID: " + i["id"])
				f.write("\nPost: " + post)
			content.append(post)
	except Exception, e:
		print e 
	if debug:
		print "\n"
		printColour("\n[>] ", CYAN)
		print "Tagged content of page: " + page
		f.write("\nTagged content of page: " + page)
	conn.request("GET", t)
	ris = conn.getresponse()
	data = ris.read()    
	JDict = json.loads(data)
	try:
		for i in JDict["data"]:
			id = i["id"]
			if "message" in i:
				post = i["message"].encode('utf-8','replace')
			else:
				post = ""
			content.append(post)
			if debug:
				printColour("\n[+] ", GREEN)
				print "ID: " + i["id"]
				printColour("[+] ", GREEN)
				print "Post: " + post
				f.write("\nID: " + i["id"])
				f.write("\nPost: " + post)
	except Exception, e:
		print e
	conn.close()
	f.close()

def getTimelineExt(page):
	f = open(os.getcwd() + '/report_' + page + '.txt', 'a')
	f.write("\nReport: " + str(datetime.now()) + " - " + page)
	r = BASE + "/" + page + "/posts?access_token=" + LONG_TERM_TOKEN
	rc = "/comments?access_token=" + LONG_TERM_TOKEN
	t = BASE + "/" + page + "/tagged?access_token=" + LONG_TERM_TOKEN
	conn = httplib.HTTPSConnection(host)
	conn.request("GET", "/" + r, headers=hdr)

	if debug:
		printColour("\n[*] ", BLUE)
		print "Getting information...\n"
	ris = conn.getresponse()
	data = ris.read()

	JDict = json.loads(data)
	content = []
	printColour("\n[>] ", CYAN)
	print "Extended Timeline of page: " + page
	f.write("\nExtended Timeline of page: " + page)
	try:
		for i in JDict["data"]:
			id = i["id"]
			if "message" in i:
				post = i["message"].encode('utf-8','replace')
			else:
				post = ""
			if debug:
				printColour("\n[+] ", GREEN)
				print "ID: " + i["id"]
				printColour("[+] ", GREEN)
				print "Post: " + post
				f.write("\nID: " + i["id"])
				f.write("\nPost: " + post)
			content.append(post)
			getComment = "/" + id + rc
			conn.request("GET", "/" + getComment)
			ris = conn.getresponse()
			data = ris.read()
			jComment = json.loads(data)
			if debug:
				printColour("\n[*] ", CYAN)
				print "List of comments"
				f.write("\nList of comments")
			if not jComment["data"]:
				if debug:
					print "No comments "
					f.write("\nNo comments ")
			else:
				for e in jComment["data"]:
					user = e["from"]["name"].encode('utf-8','replace')
					comment = e["message"].encode('utf-8','replace')
					content.append(comment)
					if debug:
						printColour("[+] ", MAGENTA)
						print "Comment from " + user + ": " + str(comment)
						f.write("\nComment from " + user + ": " + str(comment))
	except Exception, e:
		print e 

	if debug:
		print "\n"
		printColour("\n[>] ", CYAN)
		print "Tagged content of page: " + page
		f.write("\nTagged content of page: " + page)
	conn.request("GET", t)
	ris = conn.getresponse()
	data = ris.read()    
	JDict = json.loads(data)
	try:
		for i in JDict["data"]:
			id = i["id"]
			if "message" in i:
				post = i["message"].encode('utf-8','replace')
			else:
				post = ""
			content.append(post)
			if debug:
				printColour("\n[+] ", GREEN)
				print "ID: " + i["id"]
				printColour("[+] ", GREEN)
				print "Post: " + post
				f.write("\nID: " + i["id"])
				f.write("\nPost: " + post)
	except Exception, e:
		print e
	conn.close()
	f.close()

def main():
	parser = argparse.ArgumentParser(
		version=__version__,
		formatter_class=argparse.RawTextHelpFormatter,
		prog='facquire.py',
		description=__description__)
	
	parser.add_argument('-f', help='Get fingerprint (MD5 & SHA1) of Page', dest="page_f", metavar="PAGE", required=False)
	parser.add_argument('-i', help='Get basic info of Page', dest="page_i", metavar="PAGE", required=False)
	parser.add_argument('-a', help='Get full info of Page', dest="page_a", metavar="PAGE", required=False)
	parser.add_argument('-t', help='Get timeline of Page', dest="page_t", metavar="PAGE", required=False)
	parser.add_argument('-e', help='Get extended timeline of Page', dest="page_e", metavar="PAGE", required=False)
	parser.add_argument('-n', help='Get events of Page', dest="page_n", metavar="PAGE", required=False)
	parser.add_argument('-p', help='Acquire the Page', dest="page_p", metavar="PAGE", required=False)
	
	args = parser.parse_args()

	f = args.page_f
	t = args.page_t
	e = args.page_e
	i = args.page_i
	a = args.page_a
	n = args.page_n
	p = args.page_p
		
	if f:
		print __description__
		getFingerprint(f)
	elif t:
		print __description__
		getTimeline(t)
	elif e:
		print __description__
		getTimelineExt(e)
	elif i:
		print __description__
		getInfo(i)
	elif a:
		print __description__
		getFullInfo(a)
	elif n:
		print __description__
		getEvents(n)
	elif p:
		print __description__
		getFingerprint(p)
		getFullInfo(p)
		getTimelineExt(p)
		getEvents(p)

	else:
		print "Usage ./facquire.py [option]"
		print "Error arguments: missing mandatory option. Use ./facquire.py -h to help\n"
		exit()
def printColour(text, colour=WHITE):
    """
    :rtype: object
    """
    if has_colours:
        seq = "\x1b[1;%dm" % (30+colour) + text + "\x1b[0m"
        sys.stdout.write(seq)
    else:
        sys.stdout.write(text)
def has_colours(stream):
    if not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        # TODO: log console
        return False

if __name__ == "__main__":
	main()
