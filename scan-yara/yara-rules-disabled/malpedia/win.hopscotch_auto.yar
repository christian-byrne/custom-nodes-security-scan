rule win_hopscotch_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.hopscotch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hopscotch"
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
        $sequence_0 = { 8b1d???????? 8d8c24a4010000 6a00 6a00 6a03 6a00 }
            // n = 6, score = 100
            //   8b1d????????         |                     
            //   8d8c24a4010000       | lea                 ecx, [esp + 0x1a4]
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a03                 | push                3
            //   6a00                 | push                0

        $sequence_1 = { 5b 81c400010000 c3 8b8c2410010000 51 57 }
            // n = 6, score = 100
            //   5b                   | pop                 ebx
            //   81c400010000         | add                 esp, 0x100
            //   c3                   | ret                 
            //   8b8c2410010000       | mov                 ecx, dword ptr [esp + 0x110]
            //   51                   | push                ecx
            //   57                   | push                edi

        $sequence_2 = { ffd7 56 53 8d4c2414 6a08 51 e8???????? }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   56                   | push                esi
            //   53                   | push                ebx
            //   8d4c2414             | lea                 ecx, [esp + 0x14]
            //   6a08                 | push                8
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_3 = { ffd7 85c0 753c 8b35???????? ffd6 83f802 742f }
            // n = 7, score = 100
            //   ffd7                 | call                edi
            //   85c0                 | test                eax, eax
            //   753c                 | jne                 0x3e
            //   8b35????????         |                     
            //   ffd6                 | call                esi
            //   83f802               | cmp                 eax, 2
            //   742f                 | je                  0x31

        $sequence_4 = { 7554 33f6 89b5dcfeffff 8b3d???????? 83fe05 7332 }
            // n = 6, score = 100
            //   7554                 | jne                 0x56
            //   33f6                 | xor                 esi, esi
            //   89b5dcfeffff         | mov                 dword ptr [ebp - 0x124], esi
            //   8b3d????????         |                     
            //   83fe05               | cmp                 esi, 5
            //   7332                 | jae                 0x34

        $sequence_5 = { 81ec80090000 53 56 57 68???????? e8???????? }
            // n = 6, score = 100
            //   81ec80090000         | sub                 esp, 0x980
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_6 = { 68???????? e8???????? 83c408 8d9424a8020000 }
            // n = 4, score = 100
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8d9424a8020000       | lea                 edx, [esp + 0x2a8]

        $sequence_7 = { 56 57 ff15???????? 85c0 7514 8d442414 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7514                 | jne                 0x16
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_8 = { c7442400ffffffff 50 c7442408ffffffff e8???????? 83c404 8d4c2400 }
            // n = 6, score = 100
            //   c7442400ffffffff     | mov                 dword ptr [esp], 0xffffffff
            //   50                   | push                eax
            //   c7442408ffffffff     | mov                 dword ptr [esp + 8], 0xffffffff
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8d4c2400             | lea                 ecx, [esp]

        $sequence_9 = { 8b3d???????? 83c408 8d442408 50 ffd7 }
            // n = 5, score = 100
            //   8b3d????????         |                     
            //   83c408               | add                 esp, 8
            //   8d442408             | lea                 eax, [esp + 8]
            //   50                   | push                eax
            //   ffd7                 | call                edi

    condition:
        7 of them and filesize < 1143808
}