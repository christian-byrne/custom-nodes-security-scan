rule win_dyepack_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.dyepack."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dyepack"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 53 53 56 ffd7 8b442414 8b4c2410 33ed }
            // n = 7, score = 300
            //   53                   | push                ebx
            //   53                   | push                ebx
            //   56                   | push                esi
            //   ffd7                 | call                edi
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   33ed                 | xor                 ebp, ebp

        $sequence_1 = { 7cb2 7f08 8b4c2410 3be9 }
            // n = 4, score = 300
            //   7cb2                 | jl                  0xffffffb4
            //   7f08                 | jg                  0xa
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   3be9                 | cmp                 ebp, ecx

        $sequence_2 = { 8b442414 8b4c2410 33ed 33ff 3bc3 7c60 7f0a }
            // n = 7, score = 300
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   33ed                 | xor                 ebp, ebp
            //   33ff                 | xor                 edi, edi
            //   3bc3                 | cmp                 eax, ebx
            //   7c60                 | jl                  0x62
            //   7f0a                 | jg                  0xc

        $sequence_3 = { 741e 8b442418 3bc3 7416 03e8 8b442414 13fb }
            // n = 7, score = 300
            //   741e                 | je                  0x20
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   3bc3                 | cmp                 eax, ebx
            //   7416                 | je                  0x18
            //   03e8                 | add                 ebp, eax
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   13fb                 | adc                 edi, ebx

        $sequence_4 = { 1bc7 7815 7f08 81f900100000 }
            // n = 4, score = 300
            //   1bc7                 | sbb                 eax, edi
            //   7815                 | js                  0x17
            //   7f08                 | jg                  0xa
            //   81f900100000         | cmp                 ecx, 0x1000

        $sequence_5 = { 56 ff15???????? 8b8c2428100000 53 51 }
            // n = 5, score = 300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8b8c2428100000       | mov                 ecx, dword ptr [esp + 0x1028]
            //   53                   | push                ebx
            //   51                   | push                ecx

        $sequence_6 = { 3bcb 765a eb04 8b4c2410 2bcd }
            // n = 5, score = 300
            //   3bcb                 | cmp                 ecx, ebx
            //   765a                 | jbe                 0x5c
            //   eb04                 | jmp                 6
            //   8b4c2410             | mov                 ecx, dword ptr [esp + 0x10]
            //   2bcd                 | sub                 ecx, ebp

        $sequence_7 = { ff15???????? 85c0 741e 8b442418 3bc3 7416 03e8 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741e                 | je                  0x20
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]
            //   3bc3                 | cmp                 eax, ebx
            //   7416                 | je                  0x18
            //   03e8                 | add                 ebp, eax

        $sequence_8 = { 5f 5e 5b 81c414100000 c3 8b3d???????? }
            // n = 6, score = 300
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   81c414100000         | add                 esp, 0x1014
            //   c3                   | ret                 
            //   8b3d????????         |                     

        $sequence_9 = { ffd7 8d4c2418 53 51 8d54242c }
            // n = 5, score = 300
            //   ffd7                 | call                edi
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   53                   | push                ebx
            //   51                   | push                ecx
            //   8d54242c             | lea                 edx, [esp + 0x2c]

    condition:
        7 of them and filesize < 212992
}