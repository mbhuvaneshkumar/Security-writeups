# SQL Injection — Login Bypass

**Platform:** PortSwigger Web Security Academy
**Difficulty:** Apprentice
**Date:** January 11, 2026
**Status:**  Solved

---

## Objective
Log in as `administrator` without knowing the password.

---

## Vulnerability
SQL Injection in the login form's username field.
The backend query was not using parameterized queries,
allowing manipulation of authentication logic.

---

## Payload Used
- **Username:** `administrator'--`
- **Password:** `anything`

## Why It Works
The `'` closes the username string.
The `--` comments out the password check entirely.

Query becomes:
```sql
SELECT * FROM users WHERE username = 'administrator'
```
Password validation is skipped. 

---

## Impact
- Authentication bypass
- Full admin access without credentials
- Severity: **Critical (CVSS 9.8)**

---

## Fix
Use parameterized queries:
```python
cursor.execute("SELECT * FROM users 
WHERE username = ?", (username,))
```

---

## Reference
[PortSwigger SQLi Lab](https://portswigger.net/web-security/sql-injection)
