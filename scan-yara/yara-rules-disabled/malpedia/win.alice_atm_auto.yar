rule win_alice_atm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.alice_atm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alice_atm"
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
        $sequence_0 = { ff75f8 8f45fc ff7508 e8???????? 8b45fc }
            // n = 5, score = 100
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   8f45fc               | pop                 dword ptr [ebp - 4]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]

        $sequence_1 = { 0fb7c0 8945f8 8b7d10 83ff00 0f86c2000000 }
            // n = 5, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b7d10               | mov                 edi, dword ptr [ebp + 0x10]
            //   83ff00               | cmp                 edi, 0
            //   0f86c2000000         | jbe                 0xc8

        $sequence_2 = { c9 c20c00 55 8bec 81c4a4feffff }
            // n = 5, score = 100
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81c4a4feffff         | add                 esp, 0xfffffea4

        $sequence_3 = { 894609 837f0414 7305 8b5704 }
            // n = 4, score = 100
            //   894609               | mov                 dword ptr [esi + 9], eax
            //   837f0414             | cmp                 dword ptr [edi + 4], 0x14
            //   7305                 | jae                 7
            //   8b5704               | mov                 edx, dword ptr [edi + 4]

        $sequence_4 = { 897dfc 8d9df6fdffff 53 ff7508 e8???????? 0bc0 }
            // n = 6, score = 100
            //   897dfc               | mov                 dword ptr [ebp - 4], edi
            //   8d9df6fdffff         | lea                 ebx, [ebp - 0x20a]
            //   53                   | push                ebx
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   0bc0                 | or                  eax, eax

        $sequence_5 = { 57 e8???????? 0bc0 0f848b000000 53 6804010000 }
            // n = 6, score = 100
            //   57                   | push                edi
            //   e8????????           |                     
            //   0bc0                 | or                  eax, eax
            //   0f848b000000         | je                  0x91
            //   53                   | push                ebx
            //   6804010000           | push                0x104

        $sequence_6 = { 53 e8???????? 57 6806020000 56 }
            // n = 5, score = 100
            //   53                   | push                ebx
            //   e8????????           |                     
            //   57                   | push                edi
            //   6806020000           | push                0x206
            //   56                   | push                esi

        $sequence_7 = { 50 68???????? 68???????? 8d45e8 50 68???????? 6a05 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   68????????           |                     
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   68????????           |                     
            //   6a05                 | push                5

        $sequence_8 = { 6a00 6a00 6809100000 ff7320 e8???????? 8945fc }
            // n = 6, score = 100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6809100000           | push                0x1009
            //   ff7320               | push                dword ptr [ebx + 0x20]
            //   e8????????           |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_9 = { 0f85ce000000 68ea030000 ff7508 e8???????? 8bf8 }
            // n = 5, score = 100
            //   0f85ce000000         | jne                 0xd4
            //   68ea030000           | push                0x3ea
            //   ff7508               | push                dword ptr [ebp + 8]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

    condition:
        7 of them and filesize < 49152
}