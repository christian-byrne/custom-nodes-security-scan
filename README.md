> [!TIP]
>
> ## [️🛡 ️View Node Security Scan Results](https://christian-byrne.github.io/custom-nodes-security-scan)
>


&nbsp;


#### `73 Bandit Tests`

> <details>
>
> <summary>&nbsp; Test Details </summary>
>
> | Test ID | Test Name |
> |---------|-----------|
> |   B101   | assert_used                                 |
> |   B102   | exec_used                                   |
> |   B103   | set_bad_file_permissions                    |
> |   B104   | hardcoded_bind_all_interfaces               |
> |   B105   | hardcoded_password_string                   |
> |   B106   | hardcoded_password_funcarg                  |
> |   B107   | hardcoded_password_default                  |
> |   B108   | hardcoded_tmp_directory                     |
> |   B110   | try_except_pass                             |
> |   B112   | try_except_continue                         |
> |   B113   | request_without_timeout                     |
> |   B201   | flask_debug_true                            |
> |   B202   | tarfile_unsafe_members                      |
> |   B301   | pickle                                      |
> |   B302   | marshal                                     |
> |   B303   | md5                                         |
> |   B304   | ciphers                                     |
> |   B305   | cipher_modes                                |
> |   B306   | mktemp_q                                    |
> |   B307   | eval                                        |
> |   B308   | mark_safe                                   |
> |   B310   | urllib_urlopen                              |
> |   B311   | random                                      |
> |   B312   | telnetlib                                   |
> |   B313   | xml_bad_cElementTree                        |
> |   B314   | xml_bad_ElementTree                         |
> |   B315   | xml_bad_expatreader                         |
> |   B316   | xml_bad_expatbuilder                        |
> |   B317   | xml_bad_sax                                 |
> |   B318   | xml_bad_minidom                             |
> |   B319   | xml_bad_pulldom                             |
> |   B320   | xml_bad_etree                               |
> |   B321   | ftplib                                      |
> |   B323   | unverified_context                          |
> |   B324   | hashlib_insecure_functions                  |
> |   B401   | import_telnetlib                            |
> |   B402   | import_ftplib                               |
> |   B403   | import_pickle                               |
> |   B404   | import_subprocess                           |
> |   B405   | import_xml_etree                            |
> |   B406   | import_xml_sax                              |
> |   B407   | import_xml_expat                            |
> |   B408   | import_xml_minidom                          |
> |   B409   | import_xml_pulldom                          |
> |   B410   | import_lxml                                 |
> |   B411   | import_xmlrpclib                            |
> |   B412   | import_httpoxy                              |
> |   B413   | import_pycrypto                             |
> |   B415   | import_pyghmi                               |
> |   B501   | request_with_no_cert_validation             |
> |   B502   | ssl_with_bad_version                        |
> |   B503   | ssl_with_bad_defaults                       |
> |   B504   | ssl_with_no_version                         |
> |   B505   | weak_cryptographic_key                      |
> |   B506   | yaml_load                                   |
> |   B507   | ssh_no_host_key_verification                |
> |   B508   | snmp_insecure_version                       |
> |   B509   | snmp_weak_cryptography                      |
> |   B601   | paramiko_calls                              |
> |   B602   | subprocess_popen_with_shell_equals_true     |
> |   B603   | subprocess_without_shell_equals_true        |
> |   B604   | any_other_function_with_shell_equals_true   |
> |   B605   | start_process_with_a_shell                  |
> |   B606   | start_process_with_no_shell                 |
> |   B607   | start_process_with_partial_path             |
> |   B608   | hardcoded_sql_expressions                   |
> |   B609   | linux_commands_wildcard_injection           |
> |   B610   | django_extra_used                           |
> |   B611   | django_rawsql_used                          |
> |   B612   | logging_config_insecure_listen              |
> |   B701   | jinja2_autoescape_false                     |
> |   B702   | use_of_mako_templates                       |
> |   B703   | django_mark_safe                            |


#### `30 Blacklisted Python Imports`

> <details>
>
> <summary>&nbsp; Test Details </summary>
>
> | Package Name | Test ID |
> |---------|-----------|
> | telnetlib   | B401 |
> | ftplib   | B402 |
> | httpoxy   | B412 |
> | pycrypto   | B413 |
> | pyghmi   | B415 |
> | paramiko   | B601 |
> | subprocess   | B602 |
> | pip   | B816 |
> | tarfile   | B817 |
> | zipfile   | B818 |
> | importlib   | B819 |
> | imp   | B820 |
> | pkgutil   | B821 |
> | runpy   | B822 |
> | ctpyes   | B823 |
> | os.system   | B824 |
> | pty   | B825 |
> | requests.urlib   | B826 |
> | http.server   | B827 |
> | pickle   | B403 |
> | subprocess   | B404 |
> | xml.etree   | B405 |
> | xml.sax   | B406 |
> | xml.expat   | B407 |
> | xml.minidom   | B408 |
> | xml.pulldom   | B409 |
> | lxml   | B410 |
> | xmlrpclib   | B411 |
>




#### `3294 Yara Tests`

> <details>
>
> <summary>&nbsp; Test Details </summary>
>
> | Source                        | Test Name                             | File                                                                                                                                                                                                                                                                | License                           |
> |-------------------------------|---------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------|
> | telekom-security              | teabot.yar                            | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/telekom-security/flubot/teabot.yar)                                                                                                                   | Unknown                           |
> | jpcertcc                      | jpcertcc-malconfscan-rule.yara        | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/jpcertcc/jpcertcc-malconfscan-rule.yara)                                                                                                              | Unknown                           |
> | citizenlab                    | t5000.yara                            | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/citizenlab/malware-families/t5000.yara)                                                                                                               | Unknown                           |
> | malware-families              | steganography.yar                     | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/malware-families/Behavioral/steganography.yar)                                                                                                        | Unknown                           |
> | binaryalert                   | eicar.yara                            | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/binaryalert/eicar.yara)                                                                                                                               | Apache License 2.0                |
> | red_team_tool_countermeasures | HackTool_PY_ImpacketObfuscation_2.yar | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/red_team_tool_countermeasures/rules/IMPACKETOBF%20%28Wmiexec%29/production/yara/HackTool_PY_ImpacketObfuscation_2.yar)                                | Unknown                           |
> | fsf-compressed                | ft_elf.yara                           | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/fsf-compressed/ft_elf.yara)                                                                                                                           | Apache License 2.0                |
> | anyrun                        | FakeCheck.yar                         | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/anyrun/FakeCheck.yar)                                                                                                                                 | Unknown                           |
> | malpedia                      | win.winordll64_auto.yar               | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/malpedia/win.winordll64_auto.yar)                                                                                                                     | Unknown                           |
> | gcti                          | Sliver__Implant_64bit.yara            | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/gcti/Sliver/Sliver__Implant_64bit.yara)                                                                                                               | Apache License 2.0                |
> | elastic-security              | Linux_Ransomware_Conti.yar            | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/elastic-security/yara/rules/Linux_Ransomware_Conti.yar)                                                                                               | Unknown                           |
> | threat-intel                  | yara.yar                              | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/threat-intel/2022/2022-12-01%20Buyer%20Beware%20-%20Fake%20Cryptocurrency%20Applications%20Serving%20as%20Front%20for%20AppleJeus%20Malware/yara.yar) | Unknown                           |
> | trojans                       | arkei_stealer.yara                    | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/trojans/arkei_stealer.yara)                                                                                                                           | MIT License                       |
> | alienvaultlabs                | sandboxdetect.yar                     | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/alienvaultlabs/sandboxdetect.yar)                                                                                                                     | Unknown                           |
> | aa-comfy-nodes-rules          | dangerous_sites.yar                   | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/aa-comfy-nodes-rules/dangerous_sites.yar)                                                                                                             | Unknown                           |
> | jipegit                       | Shylock.yar                           | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/jipegit/Banker/Shylock.yar)                                                                                                                           | Unknown                           |
> | cyberdefenses                 | u34.yar                               | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/cyberdefenses/webshells/u34.yar)                                                                                                                      | MIT License                       |
> | security-magic                | JupyterPS.yar                         | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/security-magic/Jupyter%20Malware/JupyterPS.yar)                                                                                                       | Unknown                           |
> | cyber-defence                 | authenticode_anomalies.yara           | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/cyber-defence/authenticode_anomalies.yara)                                                                                                            | Unknown                           |
> | tenable                       | pas_web_kit.yar                       | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/tenable/webshells/pas_web_kit.yar)                                                                                                                    | Unknown                           |
> | conventionengine              | ConventionEngine.yar                  | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/conventionengine/ConventionEngine.yar)                                                                                                                | Unknown                           |
> | trellix-atr                   | Trojan_CoinMiner.yar                  | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/trellix-atr/miners/Trojan_CoinMiner.yar)                                                                                                              | Apache License 2.0                |
> | intezer                       | Rekoobe.yar                           | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/intezer/Rekoobe.yar)                                                                                                                                  | MIT License                       |
> | eset                          | badiis.yar                            | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/eset/badiis/badiis.yar)                                                                                                                               | BSD 2-Clause "Simplified" License |
> | advanced-threat-detection     | Trojan_CoinMiner.yar                  | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/advanced-threat-detection/miners/Trojan_CoinMiner.yar)                                                                                                | Apache License 2.0                |
> | si-falcon                     | windows_misc.yar                      | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/si-falcon/Windows/windows_misc.yar)                                                                                                                   | Unknown                           |
> | reversinglabs                 | Win32.Ransomware.CryptoWall.yara      | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/reversinglabs/ransomware/Win32.Ransomware.CryptoWall.yara)                                                                                            | MIT License                       |
> | yarasigs-x64dbg               | crypto_signatures.yara                | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/yarasigs-x64dbg/crypto_signatures.yara)                                                                                                               | Unknown                           |
> | f0wl                          | deathransom.yar                       | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/f0wl/windows/ransomware/deathransom.yar)                                                                                                              | MIT License                       |
> | delivr-to                     | html_wasm.yar                         | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/delivr-to/yara-rules/html_wasm.yar)                                                                                                                   | Unknown                           |
> | unprotect                     | findcrypt.yar                         | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/unprotect/findcrypt.yar)                                                                                                                              | Unknown                           |
> | deadbits                      | DNSpionage.yara                       | [source](https%3A//github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/deadbits/rules/DNSpionage.yara)                                                                                                                       | Unknown                           |
>
> [See all 3294 Yara Tests](wiki/all-yara-tests.md)
> </details>


#### `808256 Blacklisted (2022+) IPs`

>
> <details><summary>&nbsp; Click to expand</summary>
>
> | Name | Description |
> | --- | --- |
>
> </details>
>





&nbsp;

# Usage

> [!NOTE]
>
> This program uses Linux namespaces and servers, it will not work on other operating systems
>


1. Clone the repo

```bash
git clone https://github.com/christian-byrne/custom-nodes-security-scan.git
```

2. Install requirements

```bash
sudo apt install firejail yara rar
cd custom-nodes-security-scan
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

3. Edit values in [config.json](./config.json)

```bash
vim config.json
```

4. Run scan

```bash
chmod +x ./scan.sh
./scan.sh
```

# Adding Tests and Blacklists

|  Test Type | Process to Add  |
| --- | --- |
|Add blacklisted python call | edit [scan/bandit/blacklists/calls.py](https://github.com/christian-byrne/custom-nodes-security-scan/blob/master/src/scan/bandit/blacklists/calls.py) |
|Add blacklisted python import | edit [scan/bandit/blacklists/imports.py](https://github.com/christian-byrne/custom-nodes-security-scan/blob/master/src/scan/bandit/blacklists/imports.py) |
| Add blacklisted websites/domains/IPs | edit [scan/yara/yara-rules/aa-comfy-nodes-rules/dangerous-sites.yar](https://github.com/christian-byrne/custom-nodes-security-scan/blob/master/src/scan/yara/yara-rules/aa-comfy-nodes-rules/dangerous-sites.yar) |
| Add custom tests for python code | Write `.py` tests and add to [scan/bandit/plugins](https://github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/bandit/plugins) |
| Add custom yara rules | write `.yara` tests and add to [scan/yara/yara-rules/aa-comfy-nodes-rules](https://github.com/christian-byrne/custom-nodes-security-scan/tree/master/src/scan/yara/yara-rules/aa-comfy-nodes-rules) |

&nbsp; 

Then PR any changes please