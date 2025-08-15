# My PortSwigger Labs Write-ups

This repository contains my personal solutions and notes for the labs from PortSwigger's Web Security Academy. I use this to document my learning journey in web application security.

---

## SQL Injection

### 1. Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

*   Status: Solved
*   Vulnerability Type: SQL Injection
*   Description: The application was vulnerable to a basic SQL injection in the product category filter. By manipulating the category parameter in the URL, it was possible to alter the SQL query to display all products, including unreleased ones.
*   Payload Used: ' OR 1=1--
*   Steps to Reproduce:
    1.  Accessed the lab and selected a product category.
    2.  Modified the URL by appending the payload to the category parameter.
    3.  The query became logically true, causing the database to return all records.
    4.  The lab was solved upon displaying all products.

---

### 2. Lab: SQL injection vulnerability allowing login bypass

*   Status: Solved
*   Vulnerability Type: SQL Injection
*   Description: The login form was vulnerable to an SQL injection attack. It was possible to bypass the authentication mechanism by injecting a payload that made the SQL query always evaluate to true.
*   Payload Used: administrator'--
*   Steps to Reproduce:
    1.  Navigated to the login page.
    2.  Entered the payload administrator'-- in the username field.
    3.  Entered a random string in the password field.
    4.  The -- comment operator caused the rest of the query (the password check) to be ignored, resulting in a successful login as the administrator.

---
---

### 3. Lab: SQL injection UNION attack, determining the number of columns returned by the query

*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Description: The goal was to find the number of columns returned by the original query. This is the first step for any UNION-based attack.
*   Payload Used: ' UNION SELECT NULL,NULL,NULL--
*   Learning: I learned how to use a series of UNION SELECT NULL payloads to probe the database. By incrementing the number of NULL values until the query executed without error, I successfully identified that the query returns 3 columns. This knowledge is critical for structuring future attacks to exfiltrate data.
---
### 4. Lab: SQL injection UNION attack, finding a column containing text
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Description: The goal was to identify which column in the database query was compatible with string data. This is a crucial step before exfiltrating text-based information like usernames or passwords.
*   Payload Used: ' UNION SELECT NULL, 'n3lzrn', NULL--
*   Key Finding: The second column is of a string data type. This is the column that can be used to retrieve text data from other tables.
*   Link to Lab: [SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)
*   ---
### 5. Lab: SQL injection UNION attack, retrieving data from other tables
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Description: This was a full-cycle attack. First, I performed reconnaissance to determine the number of columns (2) and identify which columns were text-compatible. Then, I launched a UNION attack to exfiltrate usernames and passwords from the users table. Finally, I used the stolen administrator credentials to successfully log in and take over the account.
*   Payload Used: ' UNION SELECT username, password FROM users--
*   Stolen Credentials: administrator:ygpl5ros0xbcsnf50hkg
*   Key Finding: Successfully demonstrated the ability to not only retrieve sensitive data from a separate table but also to use that data to escalate privileges and gain administrative access.
*   Link to Lab: [SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)
