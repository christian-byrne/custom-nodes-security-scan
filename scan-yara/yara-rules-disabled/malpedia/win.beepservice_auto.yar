rule win_beepservice_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.beepservice."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.beepservice"
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
        $sequence_0 = { ffd6 8bc8 ff15???????? 50 }
            // n = 4, score = 600
            //   ffd6                 | call                esi
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     
            //   50                   | push                eax

        $sequence_1 = { 8b0d???????? 68???????? ffd6 8bc8 }
            // n = 4, score = 600
            //   8b0d????????         |                     
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   8bc8                 | mov                 ecx, eax

        $sequence_2 = { e8???????? 83f801 7505 e8???????? 68???????? 68???????? }
            // n = 6, score = 500
            //   e8????????           |                     
            //   83f801               | cmp                 eax, 1
            //   7505                 | jne                 7
            //   e8????????           |                     
            //   68????????           |                     
            //   68????????           |                     

        $sequence_3 = { 7512 6888130000 68???????? e8???????? 83c408 }
            // n = 5, score = 500
            //   7512                 | jne                 0x14
            //   6888130000           | push                0x1388
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8

        $sequence_4 = { 83c408 e9???????? 68???????? e8???????? 83c404 6a00 }
            // n = 6, score = 500
            //   83c408               | add                 esp, 8
            //   e9????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   6a00                 | push                0

        $sequence_5 = { 683f000f00 6a00 68???????? ff15???????? }
            // n = 4, score = 500
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_6 = { ff7604 68???????? e8???????? ff7608 e8???????? 83c40c }
            // n = 6, score = 400
            //   ff7604               | push                dword ptr [esi + 4]
            //   68????????           |                     
            //   e8????????           |                     
            //   ff7608               | push                dword ptr [esi + 8]
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_7 = { 83ffff 750e ff15???????? 50 68???????? eb43 }
            // n = 6, score = 400
            //   83ffff               | cmp                 edi, -1
            //   750e                 | jne                 0x10
            //   ff15????????         |                     
            //   50                   | push                eax
            //   68????????           |                     
            //   eb43                 | jmp                 0x45

        $sequence_8 = { 68???????? 57 ff15???????? 85c0 741c 3975fc }
            // n = 6, score = 400
            //   68????????           |                     
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   741c                 | je                  0x1e
            //   3975fc               | cmp                 dword ptr [ebp - 4], esi

        $sequence_9 = { ff7604 e8???????? 83f814 59 }
            // n = 4, score = 400
            //   ff7604               | push                dword ptr [esi + 4]
            //   e8????????           |                     
            //   83f814               | cmp                 eax, 0x14
            //   59                   | pop                 ecx

        $sequence_10 = { e8???????? 83f820 59 730f ff7618 68???????? e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83f820               | cmp                 eax, 0x20
            //   59                   | pop                 ecx
            //   730f                 | jae                 0x11
            //   ff7618               | push                dword ptr [esi + 0x18]
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_11 = { e8???????? ff7610 e8???????? 50 ff7610 53 e8???????? }
            // n = 7, score = 400
            //   e8????????           |                     
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   e8????????           |                     
            //   50                   | push                eax
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   53                   | push                ebx
            //   e8????????           |                     

        $sequence_12 = { 83c410 8d4c2408 6a00 6a00 }
            // n = 4, score = 300
            //   83c410               | add                 esp, 0x10
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_13 = { bf???????? a3???????? 83c404 a3???????? a3???????? 66a3???????? f3ab }
            // n = 7, score = 300
            //   bf????????           |                     
            //   a3????????           |                     
            //   83c404               | add                 esp, 4
            //   a3????????           |                     
            //   a3????????           |                     
            //   66a3????????         |                     
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_14 = { 85c0 742b 817c240400240000 7521 56 }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   742b                 | je                  0x2d
            //   817c240400240000     | cmp                 dword ptr [esp + 4], 0x2400
            //   7521                 | jne                 0x23
            //   56                   | push                esi

        $sequence_15 = { ffd7 8d442414 50 56 }
            // n = 4, score = 300
            //   ffd7                 | call                edi
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_16 = { 8bca 83e103 f3a4 8b7314 83c9ff 8bfe }
            // n = 6, score = 300
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b7314               | mov                 esi, dword ptr [ebx + 0x14]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   8bfe                 | mov                 edi, esi

        $sequence_17 = { e8???????? 83c404 50 8b4d0c 8b5114 }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   50                   | push                eax
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5114               | mov                 edx, dword ptr [ecx + 0x14]

        $sequence_18 = { e8???????? 83c408 33c0 e9???????? c785f8fdffff00240000 6a00 8d95f4fdffff }
            // n = 7, score = 200
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   c785f8fdffff00240000     | mov    dword ptr [ebp - 0x208], 0x2400
            //   6a00                 | push                0
            //   8d95f4fdffff         | lea                 edx, [ebp - 0x20c]

        $sequence_19 = { 8b0d???????? ff15???????? 8bc8 ff15???????? 8b15???????? 52 }
            // n = 6, score = 200
            //   8b0d????????         |                     
            //   ff15????????         |                     
            //   8bc8                 | mov                 ecx, eax
            //   ff15????????         |                     
            //   8b15????????         |                     
            //   52                   | push                edx

        $sequence_20 = { 8b511c 52 e8???????? 83c404 83f820 }
            // n = 5, score = 200
            //   8b511c               | mov                 edx, dword ptr [ecx + 0x1c]
            //   52                   | push                edx
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   83f820               | cmp                 eax, 0x20

        $sequence_21 = { 6a01 6a00 6a00 6a05 e8???????? 83c414 }
            // n = 6, score = 100
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a05                 | push                5
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_22 = { e8???????? 6a00 6a00 b907000000 6a00 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   b907000000           | mov                 ecx, 7
            //   6a00                 | push                0

        $sequence_23 = { c3 68e8030000 6a02 6a00 6a00 6a02 }
            // n = 6, score = 100
            //   c3                   | ret                 
            //   68e8030000           | push                0x3e8
            //   6a02                 | push                2
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   6a02                 | push                2

        $sequence_24 = { 6a04 e8???????? 83c414 85c0 7510 ff15???????? }
            // n = 6, score = 100
            //   6a04                 | push                4
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   85c0                 | test                eax, eax
            //   7510                 | jne                 0x12
            //   ff15????????         |                     

        $sequence_25 = { 50 53 c744241428010000 e8???????? }
            // n = 4, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   c744241428010000     | mov                 dword ptr [esp + 0x14], 0x128
            //   e8????????           |                     

        $sequence_26 = { bf???????? 83c9ff 33d2 b301 f2ae f7d1 49 }
            // n = 7, score = 100
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33d2                 | xor                 edx, edx
            //   b301                 | mov                 bl, 1
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx

        $sequence_27 = { b90a000000 be???????? bf???????? 33c0 f3a5 bf???????? 83c9ff }
            // n = 7, score = 100
            //   b90a000000           | mov                 ecx, 0xa
            //   be????????           |                     
            //   bf????????           |                     
            //   33c0                 | xor                 eax, eax
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff

        $sequence_28 = { 52 89442424 ff15???????? 8bf0 85f6 7505 }
            // n = 6, score = 100
            //   52                   | push                edx
            //   89442424             | mov                 dword ptr [esp + 0x24], eax
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7505                 | jne                 7

    condition:
        7 of them and filesize < 253952
}