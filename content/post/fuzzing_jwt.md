+++
author = "sh1yo"
title = "Fuzzing JWT"
date = "2022-07-26"
description = "-"
tags = [
    "web",
    "jwt"
]
+++

Sometimes you can end up in a situation where you can generate your own JWT tokens. Due to the structure of a JWT token, it’s impossible to pass it directly to the tools like [sqlmap](https://github.com/sqlmapproject/sqlmap) or [burp](https://portswigger.net/burp) intruder.

I came across such scenarios participating in CTF challenges, but this approach can be applied to real targets as well. Even if you don’t have a secret — you can still fuzz JWT headers.

### Proxy

You will need to have [mitmproxy](https://github.com/mitmproxy/mitmproxy) installed. It is a convenient tool for modifying requests and responses on  the fly with the help of simple python3 scripts.

Example mitmproxy script:

```python
def request(flow):
    flow.request.query["jwt"] = flow.request.headers["Authorization"]
		del(flow.request.headers["Authorization"])
```

It will replace the **Authorization** header with query parameter **jwt** and then delete the header.

You can run it with:

```bash
mitmproxy -p 8082 -s example_script.py
```

And then just use it as a proxy:

```bash
curl -k -x http://localhost:8082 https://example.com -H "Authorization: something"
```

The modified request and the response can be seen in the logs:

![image.png](/images/pJsiYk6jrYA1f_vsQpEUCDvIxDhmdBs0.png)

### Mitmproxy script for testing JWT tokens

```python
import json
import base64
import hmac
import hashlib

def create_signed_token(key, data):
    header = '{"typ":"JWT","alg":"HS256"}'.encode('utf-8')
    encoded_header = base64.urlsafe_b64encode(header).decode().strip('=')

    payload = data.encode('utf-8')
    encoded_payload = base64.urlsafe_b64encode(payload).decode().strip('=')

    hdata = encoded_header + '.' + encoded_payload

    d = hmac.new(key, hdata.encode('utf-8'), 'sha256')
    dig = d.digest()
    signature = base64.urlsafe_b64encode(dig).decode().strip('=')

    return hdata + '.' + signature

def request(flow):
	# get a payload from the 'jwt' query parameter
    payload = ""

    if "jwt" in flow.request.query:
        payload = flow.request.query["jwt"]
        del(flow.request.query["jwt"])

	# add the payload to the jwt body
    jwt_data = '{"role":FUZZ}'

    jwt_data = jwt_data.replace("FUZZ", json.dumps(payload))

	# generate jwt with the secret key - "secret_key"
    jwt = create_signed_token(b"secret_key", jwt_data)

	# set Authorization header with our jwt token
    flow.request.headers["Authorization"] = jwt
```

[fuzz json web tokens with mitmproxy](https://gist.github.com/Sh1Yo/65d5828aa0636a83aaf87fe614a76306)

### Testing the script

I wrote a simple flask python3 application for this purpose. It can be found [here](https://gist.github.com/Sh1Yo/26dfb6f9da34312b6f849a10933a335f). The application takes the JWT token from the **Authorization** header and prints the value of the **role** parameter within the JWT body. The secret key is **secret_key**.

Start the application and mitmproxy:

```bash
python3 main.py #runs flask app on 2222 port
mitmproxy -p 8081 -s script.py -m socks5
```

The `-m socks5` argument is needed because we are going to proxy burpsuite that supports only socks proxies.

Verifying:

```bash
curl -k --socks5 http://localhost:8081 'http://localhost:2222/?jwt=Something'
```

The application should return **Your role is Something**.

If we check the mitmproxy logs:

![image.png](/images/Jkw1id6WKcJsZTVI_C2MHmm1HA0Q-VHb)

We can see that mitmproxy successfully replaced the **jwt** parameter with the **Authorization** header that contains a valid JWT token with the `{"role":""Something"}` body.

Now we can use all the tools to test the JWT token without any additional changes. For example, sqlmap:

```bash
sqlmap -u http://localhost:2222/?jwt=something --proxy socks5://localhost:8081
```

Or even all of the burpsuite tools. For this you need to go to User options → SOCKS Proxy and write down the ip and the port of the mitmproxy. Now you can audit it manually via repeater:

![image.png](/images/FxGxC0BqER_0SJwXlRw05GkA8zQz525p)

Or use tools like intruder.

### Bonus: integration with x8

With [x8](https://github.com/Sh1Yo/x8), it’s even possible to search for parameter within the JWT token. For this purpose, replace `jwt_data = '{"role":FUZZ}'` with `jwt_data = '{"role":"user", FUZZ}'` and `json.dumps(payload)` with `payload` in the mitmproxy script.
Now you can run it with something like this:
```bash
x8 -u http://localhost:2222/?jwt=%s -t json -w wordlist -x socks5://localhost:8081
```

![image.png](/images/K4MSYkv5NZjQ3odnmTFAAwS1PMqDtHP_)

As we can see, the **Authorization** header became longer because of all those parameters. Moreover, it turned out that there were some hidden parameters within pyjwt itself!