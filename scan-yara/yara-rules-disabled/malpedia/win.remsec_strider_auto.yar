rule win_remsec_strider_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.remsec_strider."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remsec_strider"
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
        $sequence_0 = { 74f7 8b4130 2dbc97e889 f7d8 1bc0 f7d0 }
            // n = 6, score = 200
            //   74f7                 | je                  0xfffffff9
            //   8b4130               | mov                 eax, dword ptr [ecx + 0x30]
            //   2dbc97e889           | sub                 eax, 0x89e897bc
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax
            //   f7d0                 | not                 eax

        $sequence_1 = { 6a1a 58 6a10 8945e4 8945e8 58 }
            // n = 6, score = 200
            //   6a1a                 | push                0x1a
            //   58                   | pop                 eax
            //   6a10                 | push                0x10
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   58                   | pop                 eax

        $sequence_2 = { c9 c20800 55 8bec b804000100 }
            // n = 5, score = 200
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   b804000100           | mov                 eax, 0x10004

        $sequence_3 = { 85c9 74f7 8b4130 2dbc97e889 }
            // n = 4, score = 200
            //   85c9                 | test                ecx, ecx
            //   74f7                 | je                  0xfffffff9
            //   8b4130               | mov                 eax, dword ptr [ecx + 0x30]
            //   2dbc97e889           | sub                 eax, 0x89e897bc

        $sequence_4 = { 6803010000 50 ff15???????? 83c414 8d45f0 50 }
            // n = 6, score = 200
            //   6803010000           | push                0x103
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c414               | add                 esp, 0x14
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax

        $sequence_5 = { 0d00000040 50 8d85e8fdffff 50 }
            // n = 4, score = 200
            //   0d00000040           | or                  eax, 0x40000000
            //   50                   | push                eax
            //   8d85e8fdffff         | lea                 eax, [ebp - 0x218]
            //   50                   | push                eax

        $sequence_6 = { ebf5 8b432c ff30 68???????? }
            // n = 4, score = 200
            //   ebf5                 | jmp                 0xfffffff7
            //   8b432c               | mov                 eax, dword ptr [ebx + 0x2c]
            //   ff30                 | push                dword ptr [eax]
            //   68????????           |                     

        $sequence_7 = { 0510010000 68???????? 6803010000 50 }
            // n = 4, score = 200
            //   0510010000           | add                 eax, 0x110
            //   68????????           |                     
            //   6803010000           | push                0x103
            //   50                   | push                eax

        $sequence_8 = { ff772c ff15???????? 85c0 7512 ff15???????? 8bc8 }
            // n = 6, score = 200
            //   ff772c               | push                dword ptr [edi + 0x2c]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7512                 | jne                 0x14
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax

        $sequence_9 = { 85ff 7415 83ff05 7410 68???????? 6a02 }
            // n = 6, score = 200
            //   85ff                 | test                edi, edi
            //   7415                 | je                  0x17
            //   83ff05               | cmp                 edi, 5
            //   7410                 | je                  0x12
            //   68????????           |                     
            //   6a02                 | push                2

    condition:
        7 of them and filesize < 344064
}