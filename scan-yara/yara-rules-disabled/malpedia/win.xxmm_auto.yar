rule win_xxmm_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xxmm."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xxmm"
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
        $sequence_0 = { 6a00 ff15???????? 53 57 50 8945fc e8???????? }
            // n = 7, score = 600
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   53                   | push                ebx
            //   57                   | push                edi
            //   50                   | push                eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   e8????????           |                     

        $sequence_1 = { 6a00 ff55ec ff7650 8bf8 }
            // n = 4, score = 600
            //   6a00                 | push                0
            //   ff55ec               | call                dword ptr [ebp - 0x14]
            //   ff7650               | push                dword ptr [esi + 0x50]
            //   8bf8                 | mov                 edi, eax

        $sequence_2 = { 8b7c0e20 8b440e24 03f9 03c1 }
            // n = 4, score = 600
            //   8b7c0e20             | mov                 edi, dword ptr [esi + ecx + 0x20]
            //   8b440e24             | mov                 eax, dword ptr [esi + ecx + 0x24]
            //   03f9                 | add                 edi, ecx
            //   03c1                 | add                 eax, ecx

        $sequence_3 = { 897d10 3bdf 7673 8b4508 2bc6 }
            // n = 5, score = 600
            //   897d10               | mov                 dword ptr [ebp + 0x10], edi
            //   3bdf                 | cmp                 ebx, edi
            //   7673                 | jbe                 0x75
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   2bc6                 | sub                 eax, esi

        $sequence_4 = { c3 55 8bec 51 51 8b03 8b08 }
            // n = 7, score = 600
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_5 = { 0f84bc000000 397d10 0f84b3000000 3bf7 }
            // n = 4, score = 600
            //   0f84bc000000         | je                  0xc2
            //   397d10               | cmp                 dword ptr [ebp + 0x10], edi
            //   0f84b3000000         | je                  0xb9
            //   3bf7                 | cmp                 esi, edi

        $sequence_6 = { 034df8 83c0f8 d1e8 8d7a08 897df4 7450 }
            // n = 6, score = 600
            //   034df8               | add                 ecx, dword ptr [ebp - 8]
            //   83c0f8               | add                 eax, -8
            //   d1e8                 | shr                 eax, 1
            //   8d7a08               | lea                 edi, [edx + 8]
            //   897df4               | mov                 dword ptr [ebp - 0xc], edi
            //   7450                 | je                  0x52

        $sequence_7 = { 0fb74606 8945e8 85c0 7429 8b47f8 }
            // n = 5, score = 600
            //   0fb74606             | movzx               eax, word ptr [esi + 6]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   85c0                 | test                eax, eax
            //   7429                 | je                  0x2b
            //   8b47f8               | mov                 eax, dword ptr [edi - 8]

        $sequence_8 = { 3b7114 7303 8bc6 c3 53 0fb75806 57 }
            // n = 7, score = 600
            //   3b7114               | cmp                 esi, dword ptr [ecx + 0x14]
            //   7303                 | jae                 5
            //   8bc6                 | mov                 eax, esi
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   0fb75806             | movzx               ebx, word ptr [eax + 6]
            //   57                   | push                edi

        $sequence_9 = { 41 4a 75f7 8b5dfc 83c728 837de800 75d7 }
            // n = 7, score = 600
            //   41                   | inc                 ecx
            //   4a                   | dec                 edx
            //   75f7                 | jne                 0xfffffff9
            //   8b5dfc               | mov                 ebx, dword ptr [ebp - 4]
            //   83c728               | add                 edi, 0x28
            //   837de800             | cmp                 dword ptr [ebp - 0x18], 0
            //   75d7                 | jne                 0xffffffd9

    condition:
        7 of them and filesize < 540672
}