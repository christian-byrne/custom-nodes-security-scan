# icedid_analysis
This repository contains analysis scripts, YARA rules, and additional IoCs related to the blog post [Let’s set ice on fire: Hunting and detecting IcedID infections](https://www.telekom.com/en/blog/group/article/let-s-set-ice-on-fire-hunting-and-detecting-icedid-infections-627240).

- `icedid_20210507.yar`: several YARA rules to detect (binary) components of IcedID's infection chain
- `decrypt_strings_ida.py`: example implementation of core string decryption of 2021 IcedID samples using IDAPython / IDA Pro 7.6
- `compute_botid_and_regkeys.py`: computes bot ID and account-specific registry keys for IcedID's global storage
- `icedid_hashes.csv`: list of hashes that match the rules from `icedid_20210507.yar`
