+++
author = "sh1yo"
title = "[socket.io] Cross-Site Websockets Hijacking"
date = "2021-11-29"
description = ""
tags = [
    "websocket",
]
+++

The [socket.io](https://www.npmjs.com/package/socket.io) module was vulnerable to cross-site websocker hijacking attack due to the incorrect parsing of http **Origin** header.
The vulnerability was identified in 2.3.0 version.
> Socket.IO enables real-time bidirectional event-based communication

## Links
[original report](https://hackerone.com/reports/931197).

## Proof of concept:

**app.js**:
```js
var app = require('express')();
var http = require('http').createServer(app);
var io = require('socket.io')(http);

io.origins(['http://localhost:80']); //we believe that this module will decline other origins

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

io.on('connection', (socket) => {
  console.log('a user connected');
});

http.listen(80, () => {
  console.log('listening on *:80');
});
```

**index.html**:
```html
<script src="/socket.io/socket.io.js"></script>
        <script>
                var socket = io();
        </script>
```

Initial connection:

![Request and response in burpsuite](/images/5f2fc8e593ee240326150af16f94a10f625b902b.png)

**HTTP/1.1 101 Switching Protocols** means that the connection was successful.

- Try to change origin to `something.io`. `HTTP/1.1 400 Bad Request` is returned and it is good, because we allowed only localhost origin in **app.js**.

![Bad request with origin like something.io](/images/4726bb42d5c025d9fc1d8ff51158c5730cf7d93f.png)

- Change origin to **localhost`something.io**

![Bypassed](/images/eddbb41626cde8b0a25016d7398c83572438864f.png)

As we can see - the module thinks that the origin is localhost while Safari thinks that it is a subdomain of something.io. Moreover, Safari isn't the only affected browser. This works in latest Firefox as well. Just replace **`** with **$**.

## Impact

After the successful connection from the attacker's domain, the attacker can receive and send websocket messages on behalf of a user.


