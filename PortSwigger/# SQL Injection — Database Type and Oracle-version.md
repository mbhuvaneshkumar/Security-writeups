\# SQL Injection — Database Type and Version (Oracle)



Platform: PortSwigger Web Security Academy

Difficulty: Practitioner

Date: January 13, 2026

Status: Solved



\---



**## Objective**



Display the Oracle database version string 

by injecting into the product category filter.



\---



**## Vulnerability**



UNION-based SQL injection in the category 

filter parameter. Oracle databases have two 

strict requirements:



\- Every `SELECT` must include a table name

&#x20; (using `DUAL` table)

\- `UNION` columns must match data types 

&#x20; of the original query



\---



**## Payload Used**



\- \*\*Category filter:\*\* 

`'+UNION+SELECT+BANNER,+NULL+FROM+v$version--`



\---



\## Why It Works



The `UNION` appends a second query to the 

original. `v$version` is Oracle's built-in 

view containing version details. `BANNER` 

is the column holding the version string.

`--` comments out the rest of the query.



**Query becomes:**



```sql

SELECT \* FROM products WHERE category = ''

UNION SELECT BANNER, NULL FROM v$version--

```



Oracle version string is returned 

and displayed on the page.



\---



\## Impact



\- Information Disclosure

\- Database fingerprinting

\- Allows attacker to identify 

&#x20; version-specific CVEs

\- Severity: Medium (CVSS 5.3)



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

