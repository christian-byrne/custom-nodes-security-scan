rule win_feed_load_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.feed_load."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.feed_load"
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
        $sequence_0 = { 48897c2428 4d8bc5 41b940200000 e8???????? 85c0 0f84e2000000 }
            // n = 6, score = 100
            //   48897c2428           | mov                 esi, dword ptr [esp + 0x60]
            //   4d8bc5               | dec                 eax
            //   41b940200000         | lea                 eax, [eax + 0x20]
            //   e8????????           |                     
            //   85c0                 | je                  0x60a
            //   0f84e2000000         | inc                 ebp

        $sequence_1 = { 0f97c1 493bd2 eb27 4c8d42ff 418a00 4d8d4c24ff 413801 }
            // n = 7, score = 100
            //   0f97c1               | dec                 eax
            //   493bd2               | cmp                 eax, -1
            //   eb27                 | je                  0x16e7
            //   4c8d42ff             | dec                 eax
            //   418a00               | add                 edi, esi
            //   4d8d4c24ff           | inc                 esp
            //   413801               | mov                 edi, ebx

        $sequence_2 = { 41898500400000 488bfd 4d8bfa bd01000000 83fb0d 0f8c42030000 41690ab179379e }
            // n = 7, score = 100
            //   41898500400000       | mov                 eax, dword ptr [esp + 0x78]
            //   488bfd               | dec                 eax
            //   4d8bfa               | mov                 dword ptr [esp + 0x20], eax
            //   bd01000000           | dec                 eax
            //   83fb0d               | mov                 edi, eax
            //   0f8c42030000         | dec                 eax
            //   41690ab179379e       | test                eax, eax

        $sequence_3 = { 668928 e8???????? 4c8d86500c0000 488bcf e8???????? 4c8d442440 488bcf }
            // n = 7, score = 100
            //   668928               | add                 ebx, ebp
            //   e8????????           |                     
            //   4c8d86500c0000       | inc                 esp
            //   488bcf               | mov                 eax, ebx
            //   e8????????           |                     
            //   4c8d442440           | inc                 ebp
            //   488bcf               | sub                 eax, ebp

        $sequence_4 = { 7876 3b1d???????? 736e 488bc3 488bf3 48c1fe06 4c8d2d7a220200 }
            // n = 7, score = 100
            //   7876                 | mov                 ecx, dword ptr [ebp - 0x18]
            //   3b1d????????         |                     
            //   736e                 | inc                 ebp
            //   488bc3               | xor                 ecx, ecx
            //   488bf3               | mov                 edx, 0x10
            //   48c1fe06             | dec                 eax
            //   4c8d2d7a220200       | lea                 ecx, [ebp - 0x39]

        $sequence_5 = { 0f8c60040000 41837e0800 4c8d05b755ffff 7429 49635608 48035608 0fb60a }
            // n = 7, score = 100
            //   0f8c60040000         | mov                 edi, dword ptr [esp + 0xb0]
            //   41837e0800           | dec                 ecx
            //   4c8d05b755ffff       | mov                 ebp, ecx
            //   7429                 | dec                 esp
            //   49635608             | mov                 esp, dword ptr [esp + 0xa8]
            //   48035608             | inc                 ebp
            //   0fb60a               | mov                 esi, eax

        $sequence_6 = { 8bd5 ff15???????? 448bc5 488bd6 488bc8 4c8bf0 }
            // n = 6, score = 100
            //   8bd5                 | inc                 esp
            //   ff15????????         |                     
            //   448bc5               | lea                 ebp, [edi - 0x3f]
            //   488bd6               | dec                 eax
            //   488bc8               | lea                 ecx, [0x32959]
            //   4c8bf0               | mov                 byte ptr [ebx + ecx], al

        $sequence_7 = { 488bc2 4903c7 4103df 803800 75f5 3bdf 7207 }
            // n = 7, score = 100
            //   488bc2               | mov                 cl, byte ptr [ecx + edx + 0x20510]
            //   4903c7               | dec                 eax
            //   4103df               | sub                 edx, eax
            //   803800               | mov                 eax, dword ptr [edx - 4]
            //   75f5                 | shr                 eax, cl
            //   3bdf                 | dec                 ecx
            //   7207                 | mov                 dword ptr [ecx + 8], edx

        $sequence_8 = { 4c8d3de9c00100 49393cdf 7402 eb22 e8???????? 498904df }
            // n = 6, score = 100
            //   4c8d3de9c00100       | inc                 ecx
            //   49393cdf             | and                 esi, 0xf
            //   7402                 | dec                 eax
            //   eb22                 | add                 ebx, 2
            //   e8????????           |                     
            //   498904df             | movzx               edx, ax

        $sequence_9 = { 488d157b020200 488d4d88 e8???????? cc }
            // n = 4, score = 100
            //   488d157b020200       | jb                  0x102a
            //   488d4d88             | dec                 esp
            //   e8????????           |                     
            //   cc                   | mov                 edx, dword ptr [esp + 0x28]

    condition:
        7 of them and filesize < 512000
}