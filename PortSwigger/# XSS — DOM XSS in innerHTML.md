**# XSS — DOM XSS in innerHTML Sink Using Source location.search**



Platform: PortSwigger Web Security Academy

Difficulty: Apprentice

Status: Solved



\---



\## Objective



Exploit a DOM XSS vulnerability where

input from `location.search` flows

into an `innerHTML` sink.



\---



\## What I Found



The page was reading the search query

from the URL and writing it into an

element using `innerHTML`. This allowed

HTML injection on the client side.



\---



**## What I Did**



`innerHTML` doesn't execute `<script>`

tags directly so I used an image

tag with an error handler instead:



**--javascript**

**<img src=1 onerror=alert(1)>**





The image failed to load and the

`onerror` event fired the alert. 



\---



\## Why It Worked



`innerHTML` parses and renders HTML.

Even though `<script>` doesn't work

here, event handlers on HTML tags

like `onerror` do execute JavaScript.

So I used a broken image to trigger

the onerror event.



\---



\## Difference: document.write vs innerHTML



| Sink | Script tag works? | Event handlers work? |

|------|------------------|---------------------|

| document.write | Yes |  Yes |

| innerHTML |  No |  Yes |



\---



\## Impact



\- JavaScript execution via HTML events

\- Cookie stealing

\- Phishing via page manipulation

\- Severity: Medium (CVSS 6.1)



\---



\## Fix



Use `textContent` instead of `innerHTML`

for user-controlled data:



```javascript

// Vulnerable

element.innerHTML = location.search



// Safe

element.textContent = location.search

```



\---



\## Reference

\[PortSwigger DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)

