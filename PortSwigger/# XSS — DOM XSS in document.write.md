**# XSS — DOM XSS in document.write Sink Using Source location.search**



Platform: PortSwigger Web Security Academy

Difficulty: Apprentice

Status: Solved



\---



\## Objective



Exploit a DOM-based XSS vulnerability

where user input flows from

`location.search` into `document.write`.



\---



\## What I Found



The search functionality was reading

input from `location.search` and passing

it directly to `document.write` without

sanitization. This is a client-side

vulnerability — the server never

sees the payload.



\---



**## What I Did**



Entered this in the search box:



**--javascript**

**"><script>alert(1)</script>**





Alert popped up. 



\---



\## Why It Worked



The JavaScript code was doing something

like this:



**--javascript**

**document.write('<img src="' +**

**location.search + '">');**





My payload broke out of the `src`

attribute with `"` and then injected

a script tag. Since `document.write`

renders raw HTML, the browser

executed my script.



\---



\## Source and Sink Explained



| Term | Meaning |

|------|---------|

| Source | Where attacker input enters (`location.search`) |

| Sink | Where input is dangerously used (`document.write`) |



\---



\## Impact



\- Client-side script execution

\- Cookie theft

\- No server logs — harder to detect

\- Severity: Medium (CVSS 6.1)



\---



\## Fix



Never pass user-controlled data to

dangerous sinks like `document.write`.

Use `textContent` instead:



```javascript

// Vulnerable

document.write(location.search)



// Safe

element.textContent = location.search

```



\---



\## Reference

\[PortSwigger DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)

