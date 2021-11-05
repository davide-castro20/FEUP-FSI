
# Trabalho realizado na Semana #3

# CVE-2016-5734

## Information
- CVE-2016-5734
    - [cvedetails](https://www.cvedetails.com/cve/CVE-2016-5734/?q=CVE-2016-5734)
    - [cve.mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5734)

## Identification

- PhpMyAdmin did not correctly set delimiters to prevent use of the 'e' modifier of preg_replace PHP function, used for search and replace.
- So, when using this modifier, the function works like 'eval' and allows the execution of arbitrary PHP code because of improper code sanitization.
- This vulnerability is present in phpMyAdmin 4.0.x before 4.0.10.16, 4.4.x before 4.4.15.7, and 4.6.x before 4.6.3.
- The PHP versions that are vulnerable are between 4.3.0 and 5.4.6, because of regex break with null byte, fixed in 5.4.7.


## Cataloguing

- Reported by Michal Čihař (phpMyAdmin developer) and Cure53 in 2016-06-23 (according to [this Metasploit script](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/phpmyadmin_null_termination_exec.rb#L23)). 
- The vulnerability exists because of the unsafe handling of preg_replace parameters.
- The confidentiality, integrity and availability impact was partial.
- It is scored as a critical risk (9.5/10), altough the actual impact score is relatively low due to its exploitability limitations.


## Exploit

- A remote exploit was created, consisting of a few requests to the server being attacked to inject PHP code in a preg_replace call.
- A couple of versions of the exploit are available, including a [module in Metasploit](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/http/phpmyadmin_null_termination_exec.rb#L23), written in Ruby, and a [Python script](https://www.exploit-db.com/exploits/40185) developed by [@iamsecurity](https://twitter.com/iamsecurity).

## Attacks / Damage Potential

- An authenticated remote attacker could exploit these vulnerabilities to execute arbitrary PHP Code, inject SQL code, or to conduct Cross-Site Scripting attacks.
- Exploiting this vulnerability can lead to Denial of Service or remote control over the application.
- There are no reported attacks and real damage caused due to this vulnerability, as it was reported by a PhpMyAdmin developer and patched in time.
