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
---
### 6. Lab: SQL injection attack, querying the database type and version on Oracle
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Description: This lab involved identifying an SQL injection vulnerability in an Oracle database. After determining the number of columns (2), I confirmed they were both text-compatible using a UNION SELECT query against the dual table. The final payload then targeted the built-in v$version table to extract and display the full database version banner, successfully solving the lab.
*   Payload Used: ' UNION SELECT banner, NULL FROM v$version--
*   Key Finding: Successfully demonstrated the ability to perform reconnaissance on an Oracle database to identify its specific version, which is a critical first step in finding known exploits for that version.
*   Link to Lab: [SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle)
---
### 7. Lab: SQL injection attack, listing the database contents on Oracle
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Database Type: Oracle
*   Description: This lab required adapting the UNION attack methodology to an Oracle database. The core difference was the need to use the DUAL table for the SELECT statement in Oracle. I successfully enumerated the database to find the USERS table and its columns (USERNAME, PASSWORD), exfiltrated the credentials, and logged in as the administrator.
*   Payload Used: ' UNION SELECT USERNAME, PASSWORD FROM USERS--
*   Key Finding: Demonstrated adaptability by successfully executing an SQLi attack against a different database vendor (Oracle), which has a distinct syntax from PostgreSQL/MySQL. This proves a deeper understanding of the vulnerability itself, not just memorization of commands.
*   Link to Lab: [SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-on-oracle)
---
### 8. Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Tools Used: OWASP ZAP
*   Description: The objective was to identify the database type and version. Using OWASP ZAP to intercept and modify requests, I determined the column count was two. I then faced an Internal Server Error when placing the @@version payload in the first column, indicating a data type mismatch. By moving the payload to the second column, I successfully bypassed the error and exfiltrated the database version string.
*   Payload Used: ' UNION SELECT NULL, @@version#
*   Key Finding: Successfully identified the database as MySQL/Microsoft. This lab demonstrated critical real-world skills in error analysis, payload adjustment, and the use of professional proxy tools like OWASP ZAP.
*   Link to Lab: [SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-on-mysql-and-microsoft)
---
### 9. Lab: SQL injection attack, listing the database contents on non-Oracle databases
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Description: Executed a full-cycle attack to enumerate and exfiltrate data from a non-Oracle database. The process involved first identifying the number of columns and text-compatible columns. Then, I queried the database's schema to discover table and column names, specifically finding the users table and the username and password columns. Finally, I extracted the administrator's credentials and used them to log in and take over the account.
*   Payload Used (Example): ' UNION SELECT table_name, NULL FROM information_schema.tables-- (To find tables), followed by ' UNION SELECT username, password FROM users-- (To exfiltrate data).
*   Key Finding: Successfully demonstrated the ability to systematically explore a database schema, identify sensitive tables and columns, and extract credentials to achieve full account takeover.
*   Link to Lab: [SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-on-non-oracle)
---
### 10. Lab: SQL injection UNION attack, retrieving multiple values in a single column
*   Status: Solved
*   Vulnerability Type: SQL Injection (UNION Attack)
*   Description: This lab presented a significant challenge where only one column in the query results was compatible with text data. To overcome this, I utilized database-specific concatenation techniques to combine multiple data fields (username and password) into that single column, separated by a custom delimiter. This allowed for the successful exfiltration of credentials, leading to administrator account takeover.
*   Payload Used (Example for PostgreSQL): ' UNION SELECT username || '~' || password, NULL FROM users--
*   Key Finding: Demonstrated the ability to adapt to strict output constraints by using concatenation to exfiltrate multiple values through a single available text column. This is a crucial skill for real-world scenarios where output is limited.
*   Link to Lab: [SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)
---
### 11. Lab: Blind SQL injection with conditional responses
*   Status: Solved
*   Vulnerability Type: Blind SQL Injection (Boolean-based)
*   Tools Used: Burp Suite (Intruder)
*   Description: This lab marked a significant step into advanced techniques. With no direct output from the database, I had to exfiltrate data by asking a series of true/false questions. Using Burp Suite's Intruder tool, I automated the process of sending conditional queries via a tracking cookie to determine the correct characters of the administrator's password one by one, based on the presence of a "Welcome back!" message in the response.
*   Payload Used (Example Logic): ... ' AND (SELECT SUBSTRING(password, {§1§}, 1) FROM users WHERE username = 'administrator') = '{§a§}'-- (Configured in Burp Intruder)
*   Key Finding: Successfully demonstrated the ability to perform a meticulous, character-by-character data exfiltration using boolean-based blind SQL injection. This proves a deep, inferential understanding of database interactions and proficiency with professional tools like Burp Suite Intruder for automating complex attacks.
*   Link to Lab: [Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditio
*   nal-responses)
---
### 12. Lab: Blind SQL injection with conditional errors
*   Status: Solved
*   Vulnerability Type: Blind SQL Injection (Error-based)
*   Tools Used: Burp Suite (Intruder)
*   Description: This lab required a different blind injection technique. Instead of relying on a positive response, I intentionally triggered database errors to confirm true conditions. By injecting a CASE statement that caused a division-by-zero error only when a character guess was correct, I could infer the administrator's password. The entire process was automated using Burp Suite's Intruder to systematically test each character.
*   Payload Used (Example Logic): ... '||(SELECT CASE WHEN (SUBSTR(password,{§1§},1)='{§a§}') THEN to_char(1/0) ELSE '' END FROM users WHERE username='administrator')||' (Configured in Burp Intruder)
*   Key Finding: Successfully demonstrated proficiency in error-based blind SQL injection, a powerful technique for when an application suppresses positive feedback but still reveals errors. This showcases adaptability and a deeper understanding of database error han---
### 13. Lab: Visible error-based SQL injection
*   Status: Solved
*   Vulnerability Type: Error-based SQL Injection
*   Tools Used: Burp Suite (Repeater)
*   Description: This lab demonstrated a highly efficient data exfiltration technique. Instead of inferring data bit by bit, I forced the database to disclose sensitive information directly within its error messages. By injecting a query that attempted to cast a text-based password to an integer, the application returned a verbose error message that included the full password, allowing for immediate data theft and account takeover.
*   Payload Used (Example Logic): ' AND CAST((SELECT password FROM users LIMIT 1) as int)--
*   Key Finding: Mastered the technique of triggering and manipulating verbose database error messages to exfiltrate data in a single request, a much faster method than blind injection techniques. This showcases an ability to leverage application misconfigurations for maximum impact.
*   Link to Lab: [Visible error-based SQL injection](https://portswigger.net/web-security/sql-injection/error-based/lab-visible-error-based)dling.
*   Link to Lab: [Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
---
### 14. Lab: Blind SQL injection with time delays
*   Status: Solved
*   Vulnerability Type: Blind SQL Injection (Time-based)
*   Tools Used: Burp Suite (Repeater / Intruder)
*   Description: This lab required the ultimate blind injection technique for scenarios where the application gives no differential feedback in its response body. I injected database-specific commands (e.g., pg_sleep()) that force the database to pause for a set duration if a condition is true. By monitoring the response times in Burp Suite, I could infer the data bit by bit, demonstrating a successful attack even against a completely 'silent' application.
*   Payload Used (Example Logic): '||(SELECT CASE WHEN (username='administrator' AND SUBSTR(password,1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users)--
*   Key Finding: Mastered time-based blind SQL injection, the final resort for data exfiltration when no other feedback channel is available. This showcases the ability to exploit the most subtle information leaks (response time) and demonstrates a comprehensive understanding of advanced SQL injection methodologies.
*   Link to Lab: [Blind SQL injection with time delays](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays)
---
### 15. Lab: Blind SQL injection with time delays and information retrieval
*   Status: Solved
*   Vulnerability Type: Blind SQL Injection (Time-based Data Exfiltration)
*   Tools Used: Burp Suite (Intruder)
*   Description: This advanced lab combined two skills: time-based blind injection and automated data retrieval. I crafted a payload using a CASE statement and a database-specific sleep command (pg_sleep). This payload would only cause a time delay if the guessed character in the administrator's password was correct. I then used Burp Intruder to automate the process, iterating through all possible characters for each position to successfully exfiltrate the full password without any direct feedback from the application.
*   Payload Used (Example Logic): ';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,§1§,1)='§a§') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users-- (Configured in Burp Intruder)
*   Key Finding: Successfully demonstrated the ability to perform a fully automated, time-based blind SQL injection attack to exfiltrate sensitive data. This is a critical skill for the most challenging real-world scenarios where applications are completely hardened against feedback.
*   Link to Lab: [Blind SQL injection with time delays and information retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)
---
### Labs 15 & 16: Out-of-Band (OAST) SQL Injection
*   Status: Investigated & Understood (Unsolved due to platform constraints)
*   Vulnerability Type: Blind SQL Injection (Out-of-Band Interaction & Data Exfiltration)
*   Investigation Summary: These labs require triggering an out-of-band network interaction to a server controlled by the tester. I successfully set up and ran a free, open-source alternative to Burp Collaborator (Project Discovery's Interactsh). However, after thorough investigation and reading the lab's official notes, it was confirmed that the Academy's firewall is intentionally configured to block all external connections except those to the official Burp Collaborator server. This makes solving these specific labs impossible without a Burp Suite Professional license.
*   Key Finding & Skill Learned: The primary lesson was not in the attack itself, but in troubleshooting and problem diagnosis. I learned how to set up and use OAST tools and, more importantly, how to identify when a failure is caused by environmental constraints (like a firewall) rather than a flawed payload. This is a critical real-world skill. I am proficient in the OAST technique and can apply it in real-world scenarios without such restrictions.
*   Link to Lab 15: [Blind SQL injection with out-of-band interaction](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band)
*   Link to Lab 16: [Blind SQL injection with out-of-band data exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)
*   ---
### 17. Lab: SQL injection with filter bypass via XML encoding
*   Status: Solved
*   Vulnerability Type: SQL Injection (Filter Bypass)
*   Tools Used: Burp Suite (Repeater), XML Encoding
*   Description: This final lab presented a Web Application Firewall (WAF) that blocked common SQL injection keywords and characters. The vulnerability was in a function that processed XML data. I successfully bypassed the filter by replacing the blocked characters (like spaces and single quotes) with their XML entity-encoded equivalents (e.g., &#x20; for a space). This allowed the payload to pass through the WAF undetected and be correctly interpreted by the back-end database, leading to a successful UNION attack and full credential exfiltration.
*   Payload Used (Example Logic): 1&#x20;UNION&#x20;SELECT&#x20;username,&#x20;password&#x20;FROM&#x20;users-- (with all necessary characters encoded)
*   Key Finding: Mastered the critical skill of bypassing security filters (WAFs) by using alternative encodings. This demonstrates an understanding of not just the vulnerability, but also the defense mechanisms and how to circumvent them, a highly valuable skill in professional penetration testing.
*   Link to Lab: [SQL injection with filter bypass via XML encoding](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)
---
## 2. Cross-Site Scripting (XSS)

### 18. Lab: Reflected XSS into HTML context with nothing encoded
*   Status: Solved
*   Vulnerability Type: Reflected Cross-Site Scripting (XSS)
*   Description: This was the first lab in the XSS module. The goal was to inject a script into a search query that would be reflected back on the results page and executed by the browser. The application had no encoding or filtering defenses, making it a straightforward injection.
*   Payload Used: <script>alert(1)</script>
*   Key Finding: Successfully demonstrated a fundamental understanding of Reflected XSS by injecting a simple script payload into an unprotected input field, causing arbitrary JavaScript to execute in the user's browser. This marks the beginning of my journey into client-side vulnerabilities.
*   Link to Lab: [Reflected XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded)
*   ### 19. Lab: Stored XSS into HTML context with nothing encoded
*   Status: Solved
*   Vulnerability Type: Stored Cross-Site Scripting (XSS)
*   Description: This lab demonstrated the impact of Stored XSS. I submitted a comment containing a script payload. The application stored this comment in its database without proper sanitization. As a result, the script was permanently embedded in the blog post page and executed in the browser of every user who visited it.
*   Payload Used: <script>alert(1)</script>
*   Key Finding: Successfully executed a Stored XSS attack, highlighting the difference from Reflected XSS. This type of vulnerability is more severe as it affects all users who view the compromised page, not just those who click a malicious link. This showcases an ability to create persistent threats.
*   Link to Lab: [Stored XSS into HTML context with nothing encoded](https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded)
---
### 20. Lab: DOM XSS in document.write sink using source location.search
*   Status: Solved
*   Vulnerability Type: DOM-based Cross-Site Scripting (XSS)
*   Description: This was my first DOM XSS challenge. The key was to analyze the client-side JavaScript code to identify the source (where user input comes from) and the sink (where it's executed). I discovered that the application was taking input directly from the URL (location.search) and writing it to the page using document.write without any sanitization. This allowed me to craft a URL that executed arbitrary JavaScript.
*   Payload Used: ?search=<script>alert(1)</script>
*   Key Finding: Successfully identified and exploited a classic Source-to-Sink DOM XSS vulnerability, demonstrating an understanding of client-side code analysis.
*   Link to Lab: [DOM XSS in document.write sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink)

---
### 21. Lab: DOM XSS in innerHTML sink using source location.search
*   Status: Solved
*   Vulnerability Type: DOM-based Cross-Site Scripting (XSS)
*   Description: Similar to the previous lab, but this time the sink was innerHTML. While innerHTML can sometimes be tricky, the lack of input filtering made it vulnerable. I constructed a payload with an img tag and an invalid src attribute, using the onerror event to trigger the JavaScript payload when the image failed to load.
*   Payload Used: ?search=<img src=1 onerror=alert(1)>
*   Key Finding: Demonstrated the ability to exploit an innerHTML sink, a common but sometimes misunderstood vulnerability. This required using an event handler (onerror) to achieve code execution, showcasing a more creative approach to payload construction.
*   Link to Lab: [DOM XSS in innerHTML sink using source location.search](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink)
---
### 22. Lab: DOM XSS in jQuery anchor href attribute sink using location.search source
*   Status: Solved
*   Vulnerability Type: DOM-based XSS (jQuery Sink)
*   Description: This lab introduced jQuery. I analyzed the client-side code and found it was using location.search to populate the href attribute of a link. By using the javascript: protocol, I was able to turn the link itself into an executable payload, demonstrating an understanding of how to exploit sinks within common JavaScript libraries.
*   Payload Used: ?returnUrl=javascript:alert(1)
*   Key Finding: Successfully exploited a DOM XSS vulnerability within a jQuery context, proving the ability to analyze and attack third-party library implementations.
*   Link to Lab: [DOM XSS in jQuery anchor href attribute sink using location.search source](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink)

---
### 23. Lab: DOM XSS in jQuery selector sink using a hashchange event
*   Status: Solved
*   Vulnerability Type: DOM-based XSS (Event-based)
*   Description: This was a highly advanced lab. The vulnerability was not triggered on page load, but on a hashchange event. I had to craft a payload that used the URL's hash (#) to select an element on the page and trigger an event. This required a deep understanding of how jQuery selectors and browser events work together.
*   Payload Used: https://LAB-ID.web-security-academy.net/#<img src=1 onerror=alert(1)>
*   Key Finding: Mastered event-based DOM XSS, a subtle but powerful attack vector. This shows an ability to find vulnerabilities that are not immediately apparent and require user interaction or specific browser events to trigger.
*   Link to Lab: [DOM XSS in jQuery selector sink using a hashchange event](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hashchange-event)

---
### 24. Lab: Reflected XSS into attribute with angle brackets HTML-encoded
*   Status: Solved
*   Vulnerability Type: Reflected XSS (Bypassing HTML Encoding)
*   Description: This was my first challenge involving bypassing a security filter. The application was encoding < and > characters, preventing standard script tags. The key was to realize I was already inside an HTML tag. I broke out of the existing attribute by closing it with a " and then added a new event handler (onmouseover) to execute my payload.
*   Payload Used:  " onmouseover="alert(1)
*   Key Finding: Successfully bypassed a common XSS defense (HTML entity encoding) by manipulating the HTML attribute context. This is a fundamental skill in real-world penetration testing.
*   Link to Lab: [Reflected XSS into attribute with angle brackets HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded)
---
### 25. Lab: Stored XSS into anchor href attribute with double quotes HTML-encoded
*   Status: Solved
*   Vulnerability Type: Stored XSS (Bypassing HTML Encoding)
*   Description: This lab combined Stored XSS with filter evasion. The application stored user input in an href attribute but encoded double quotes, preventing the use of event handlers. The solution was to use the javascript: protocol directly in the URL field, creating a permanent malicious link on the page.
*   Payload Used: javascript:alert(1)
*   Key Finding: Successfully bypassed double-quote encoding in a stored context by using the javascript: URI scheme, a classic and effective technique.
*   Link to Lab: [Stored XSS into anchor href attribute with double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded)

---
### 26. Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded
*   Status: Solved
*   Vulnerability Type: Reflected XSS (JavaScript String Escape)
*   Description: This was a critical challenge that taught me how to escape from a JavaScript string context. The application placed my input inside a JavaScript variable, but encoded angle brackets. The solution was to terminate the string with a single quote ('), add a logical operator (-), and then inject my JavaScript code, followed by a comment (//) to neutralize the rest of the original script.
*   Payload Used: '-alert(1)//
*   Key Finding: Mastered the technique of breaking out of a JavaScript string context. This is a fundamental skill for exploiting XSS in modern web applications that heavily rely on client-side scripting.
*   Link to Lab: [Reflected XSS into a JavaScript string with angle brackets HTML encoded](https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded)
---
### 27. Lab: DOM XSS in document.write sink using source location.search inside a select element
*   Status: Solved
*   Level: Practitioner
*   Vulnerability Type: DOM-based XSS (Context-aware Evasion)
*   Description: This lab required escaping a highly restrictive HTML context. The sink was inside a <select> element, which doesn't render most HTML tags. The solution was to close the <select> and <option> tags first, and then inject a standard XSS payload.
*   Payload Used: ?storeId=</option></select><img src=1 onerror=alert(1)>
*   Key Finding: Demonstrated the ability to perform context-aware payload construction, understanding the specific limitations of an HTML element and crafting a payload to break out of it.
*   Link to Lab: [DOM XSS in document.write sink using source location.search inside a select element](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element)

---
### 28. Lab: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
*   Status: Solved
*   Level: Practitioner
*   Vulnerability Type: DOM-based XSS (AngularJS Sandbox Escape)
*   Description: A major milestone. This lab involved exploiting an XSS vulnerability in a modern JavaScript framework (AngularJS). Standard payloads were blocked by encoding and the AngularJS sandbox. The solution was to use an AngularJS expression that executes code without needing standard script tags or event handlers, bypassing the sandbox.
*   Payload Used: {{constructor.constructor('alert(1)')()}}
*   Key Finding: Successfully exploited a framework-specific vulnerability, proving the ability to adapt attack techniques to modern, complex client-side environments. This is a highly valuable skill.
*   Link to Lab: [DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-angularjs-expression)

---
### 29. Lab: Reflected DOM XSS
*   Status: Solved
*   Level: Practitioner
*   Vulnerability Type: Hybrid XSS (Reflected DOM-based)
*   Description: This lab showcased a hybrid vulnerability where a server-side reflection was processed by client-side JavaScript. The server reflected input into a JavaScript string, which was then used in a dangerous sink. The key was to escape the JavaScript string on the server-side to create a valid DOM XSS payload on the client-side.
*   Payload Used: \"-alert(1)}//
*   Key Finding: Understood and exploited a hybrid Reflected+DOM vulnerability, demonstrating a holistic view of how server-side and client-side code can interact to create security flaws.
*   Link to Lab: [Reflected DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-reflected-dom-xss)

---
### 30. Lab: Stored DOM XSS
*   Status: Solved
*   Level: Practitioner
*   Vulnerability Type: Hybrid XSS (Stored DOM-based)
*   Description: Similar to the previous lab, but with a stored vector. The server stored user input which was later processed insecurely by client-side JavaScript. The attack involved crafting a payload that, when retrieved from the database, would trigger a DOM-based XSS. This makes the attack persistent and more dangerous.
*   Payload Used: "><img src=1 onerror=alert(1)>
*   Key Finding: Mastered the concept of Stored DOM XSS, where a server-side stored value becomes a client-side attack vector. This demonstrates an understanding of the full lifecycle of a persistent XSS attack.
*   Link to Lab: [Stored DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-stored-dom-xss)
