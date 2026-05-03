**# XSS — Stored XSS into HTML Context with Nothing Encoded**



Platform: PortSwigger Web Security Academy

Difficulty: Apprentice

Status: Solved



\---



\## Objective



Inject a persistent XSS payload into the

comment section that executes when anyone

visits the page.



\---



\## What I Found



The comment field stored user input

directly into the database without

sanitization. The stored content was

then rendered as raw HTML for every

visitor.



\---



**## What I Did**



Entered this payload in the comment box:



**```javascript**

**<script>alert(1)</script>**

**```**



Submitted the comment. When the page

loaded again the alert fired

automatically. 



\---



\## Why It Worked



Unlike Reflected XSS where the payload

needs to be in the URL, Stored XSS saves

the payload in the database. Every time

anyone visits the page the script runs

automatically — making it much more

dangerous.



\---



\## Difference: Reflected vs Stored XSS



| Type | Where payload lives | Who gets affected |

|------|-------------------|------------------|

| Reflected | URL parameter | Only victim who clicks link |

| Stored | Database | Every visitor to the page |



\---



\## Impact



\- Affects every user visiting the page

\- Session hijacking at scale

\- Defacement of web page

\- Severity: High (CVSS 8.0)



\---



\## Fix



Sanitize input before storing in database

and encode output before rendering:



```python

import html

safe = html.escape(user\_input)

```



\---



\## Reference

\[PortSwigger Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)

