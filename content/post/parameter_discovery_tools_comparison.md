+++
author = "sh1yo"
title = "Parameter discovery tools comparison"
date = "2021-07-01"
draft = true
description = "The comparison between x8, Arjun and Param Miner."
tags = [
    "tools",
    "content-discovery"
]
+++

Some people asked me about publishing a comparison between [x8](https://github.com/sh1yo/x8) and other major tools for parameter discovery: [Arjun](https://github.com/s0md3v/Arjun/) and [Param Miner](https://github.com/PortSwigger/param-miner), so here it is!

Parameter discovery tools help to find parameters that can be vulnerable or able to reveal some hidden features. In this post, I am going to check the speed and accuracy of these tools. For tests, I used a [wordlist](https://twitter.com/sh1yo_/status/1410862366275817472?s=20) with 26k parameters. If you don't have time to read the whole post - you can go directly to the summary at the end of a page.

## Tools

#### [x8 v2.0.0](https://github.com/sh1yo/x8)
Used --disable-custom-parameters flag because none of the other testing tools has this functionality.

#### [arjun v2.1.3](https://github.com/s0md3v/Arjun/)
Used -c 256 flag because the initial amount of parameters per request is too huge and some pages ignore the rest of the parameters or throw some errors. Also, I modified error\_handler.py:29 because it causes the tool to stop on 400 HTTP code.

#### [param miner v1.28](https://github.com/PortSwigger/param-miner)
Used disable origin cachebuster, disable basic wordlist, force bucketsize = 256 (sometimes works very bad and sends 6-12 parameters per request), disable response (this flag allows the tool to search parameters in every response. I don't like it because sometimes it increases the number of requests by a few times), use custom wordlist flags.<br>
Default request:
```http
GET /PATH HTTP/1.1
Host: host
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36
Accept-Charset: utf-8, iso-8859-1;q=0.5, *;q=0.1
Accept-Language: en-US, *;q=0.5
Accept: */*
```

## Targets

To perform the comparison I chose my test domain and a few popular domains like google.com, yandex.ru, github.com, youtube.com, then I ran a crawler on these domains and selected the most interesting paths.<br>
Some info about custom targets: 4rt.one and 4rt.one/json contain a lot of different parameters that, I believe, can cover most of the real-life cases.

## Results

### Accuracy

The next tables show the statistic across 10 endpoints.

#### Parameters found by every tool and how many requests did it take
<table>
<tr style="background-color:#484848;color:white;">
<th>x8</th>
<th>requests</th>
<th>parameters</th>
</tr>
<tr>
<td>4rt.one</td>
<td>231</td>
<td>admin, copy, email, facebook, test, z</td>
</tr>
<tr>
<td> * 4rt.one/json?filename=sth</td>
<td>104</td>
<td>email, role, tag, username</td>
</tr>
<tr>
<td>www.google.com</td>
<td>217</td>
<td>
<details>
<summary>37 parameters</summary>
ad, client, complete, cr, dnr, domains, gc, gcs, gl, gll, gm, gpc, gr, h, host, hq, imgtype, imgurl, interests, lr, lsf, pws, q, query, rcu, rls, rlz, sab, si, sie, sky, sz, tbm, tnm, ur, v, w
</details>
</td>
</tr>
<tr>
<td>www.google.com/services</td>
<td>147</td>
<td>rs, sqp</td>
</tr>
<tr>
<td>www.google.com/advanced\_search</td>
<td>156</td>
<td>as\_epq, as\_eq, as\_filetype, as\_nhi, as\_nlo, as\_oq, as\_q, as\_sitesearch, cr, q, query, tbm</td>
</tr>
<tr>
<td>yandex.ru/company</td>
<td>165</td>
<td>from, tag</td>
</tr>
<tr>
<td>github.com/about</td>
<td>148</td>
<td>page, q, return\_to, utm\_campaign, utm\_medium, utm\_source, utm\_term</td>
</tr>
<tr>
<td>www.youtube.com/about/</td>
<td>147</td>
<td>rs, sqp</td>
</tr>
<tr>
<td>www.youtube.com/t/terms</td>
<td>130</td>
<td>auth</td>
</tr>
<tr>
<td>www.youtube.com/new</td>
<td>156</td>
<td>auth, bp, cbr, cos, pbj, spf</td>
</tr>

<tr style="background-color:#484848;color:white;">
<th>arjun</th>
<th>reqs</th>
<th>parameters</th>
</tr>
<tr>
<td>4rt.one</td>
<td>167</td>
<td>z, facebook, test, email</td>
</tr>
<tr>
<td> * 4rt.one/json?filename=sth</td>
<td>infinity loop of requests</td>
<td></td>
</tr>
<tr>
<td>www.google.com</td>
<td>119</td>
<td>
tbm
</td>
</tr>
<tr>
<td>www.google.com/services</td>
<td>135</td>
<td>rs, sqp</td>
</tr>
<tr>
<td>www.google.com/advanced\_search</td>
<td>124</td>
<td>tbm</td>
</tr>
<tr>
<td>yandex.ru/company</td>
<td>103</td>
<td></td>
</tr>
<tr>
<td>github.com/about</td>
<td>133</td>
<td>page, id</td>
</tr>
<tr>
<td>www.youtube.com/about/</td>
<td>133</td>
<td>rs, sqp</td>
</tr>
<tr>
<td>www.youtube.com/t/terms</td>
<td>106</td>
<td>auth</td>
</tr>
<tr>
<td>www.youtube.com/new</td>
<td>105</td>
<td></td>
</tr>

<tr style="background-color:#484848;color:white;">
<th>param miner</th>
<th>reqs</th>
<th>parameters</th>
</tr>
<tr>
<td>4rt.one</td>
<td>372</td>
<td>copy, test, z</td>
</tr>
<tr>
<td> * 4rt.one/json?filename=sth</td>
<td>132</td>
<td>email, tag, username</td>
</tr>
<tr>
<td>www.google.com</td>
<td>1178</td>
<td>
ad, client, complete, cr, domains, tbm, tnm, lr, pws, rcu, rlz, tnm, ur
</td>
</tr>
<tr>
<td>www.google.com/services</td>
<td>255</td>
<td>rs, sqp</td>
</tr>
<tr>
<td> ** www.google.com/advanced\_search</td>
<td>429</td>
<td>as\_epq, as\_eq, as\_filetype, as\_nhi, as\_nlo, as\_oq, as\_q, as\_sitesearch, cr, q, query, tbm</td>
</tr>
<tr>
<td>yandex.ru/company</td>
<td>294</td>
<td>from, tag</td>
</tr>
<tr>
<td>github.com/about</td>
<td>132</td>
<td></td>
</tr>
<tr>
<td>www.youtube.com/about/</td>
<td>253</td>
<td>rs, sqp</td>
</tr>
<tr>
<td>www.youtube.com/t/terms</td>
<td>179</td>
<td>auth</td>
</tr>
<tr>
<td>www.youtube.com/new</td>
<td>292</td>
<td>auth, bp</td>
</tr>
</table>

\* - send parameters via json body. 512 parameters per request<br>
\*\* - as\_parameters were manually added to the list because I disabled searching words in the response

#### Average number of requests needed for 1 parameter

<table>
<tr style="background-color:#484848;color:white;">
<th>tool</th>
<th>requests per parameter</th>
</tr>
<tr>
<td>x8</td>
<td>54</td>
</tr>
<tr>
<td>arjun</td>
<td>85</td>
</tr>
<tr>
<td>param miner</td>
<td>118</td>
</tr>
</table>

I removed www.google.com/ from the count in this and the second table because 45% of the parameters were found there.

#### Missing parameters

<table>
<tr style="background-color:#484848;color:white;">
<th>tool</th>
<th>Count</th>
<th>%</th>
</tr>
<tr>
<td>x8</td>
<td>1</td>
<td>2</td>
</tr>
<tr>
<td>arjun</td>
<td>29</td>
<td>70</td>
</tr>
<tr>
<td>param miner</td>
<td>16</td>
<td>36</td>
</tr>
</table>

### Speed

The next table represents a speed of each tool. Target used - 4rt.one/load?size=n on localhost.
I am making comparisons on my laptop with: <br>
OS: 5.12.9-arch1-1<br>
CPU: Intel i3-7020U

<table>
<tr style="background-color:#484848;color:white;">
<th>tool</th>
<th>size=10(300kb)</th>
<th>size=25(750kb)</th>
<th>size=50(1500kb)</th>
<th>speed</th>
</tr>
<tr>
<td> * ** x8</td>
<td>10.144s</td>
<td>22.232s</td>
<td>44.784s</td>
<td>1</td>
</tr>
<tr>
<td>x8 7 threads</td>
<td>9.360s</td>
<td>22.085s</td>
<td>44.288s</td>
<td></td>
</tr>
<tr>
<td>arjun</td>
<td>14.174s</td>
<td>28.956s</td>
<td>52.904s</td>
<td>0.8</td>
</tr>
<tr>
<td>arjun 7 threads</td>
<td>13.161s</td>
<td>28.821s</td>
<td>53.768s</td>
<td></td>
</tr>
<tr>
<td>param miner</td>
<td>10s</td>
<td>37s</td>
<td>61s</td>
<td>0.71</td>
</tr>
</table>

\*\*\* - Force 256 parameters per request as well as in other tools.

## Summary
<table>
<tr style="background-color:#484848;color:white;">
<th>#</th>
<th>tool</th>
<th>requests per parameter</th>
<th>accuracy</th>
<th>speed</th>
</tr>
<tr>
<th>1</th>
<td>x8</td>
<td>54</td>
<td>98%</td>
<td>1</td>
</tr>
<tr>
<th>2</th>
<td>param miner</td>
<td>118</td>
<td>64%</td>
<td>0.71</td>
</tr>
<tr>
<th>3</th>
<td>arjun</td>
<td>85</td>
<td>30%</td>
<td>0.8</td>
</tr>
</table>

## Final thoughts & conclusion

Anyway, some stats can be very inaccurate due to the small number of test endpoints and the inability to know the exact number of parameters, but yet they are able to show a rough picture. Most of the time param miner and arjun fails to detect parameters with a different number of reflections and some difficult cases.<br>

Feel free to suggest other tools and endpoints in <a href="https://t.me/sh1y0">telegram</a> or <a href="https://twitter.com/sh1yo_">twitter</a>. If you believe you found a mistake in the data - compare the versions of your tools with the tested versions and make sure you run the tool at least 3-4 times because sometimes results can be different each run. If the version of tools is correct and the main part of tries gives you different results - write to me.<Paste>
