rule win_w32times_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.w32times."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.w32times"
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
        $sequence_0 = { e8???????? 85c0 0f8487030000 6a01 68???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8487030000         | je                  0x38d
            //   6a01                 | push                1
            //   68????????           |                     

        $sequence_1 = { 83e103 f3a4 8b35???????? 8d8c24f0020000 68???????? 51 ffd6 }
            // n = 7, score = 200
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8b35????????         |                     
            //   8d8c24f0020000       | lea                 ecx, [esp + 0x2f0]
            //   68????????           |                     
            //   51                   | push                ecx
            //   ffd6                 | call                esi

        $sequence_2 = { 83c408 68???????? ff15???????? 85c0 0f85c6060000 ff15???????? }
            // n = 6, score = 200
            //   83c408               | add                 esp, 8
            //   68????????           |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85c6060000         | jne                 0x6cc
            //   ff15????????         |                     

        $sequence_3 = { ff15???????? 68???????? ff15???????? 396c2418 7410 6a01 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   396c2418             | cmp                 dword ptr [esp + 0x18], ebp
            //   7410                 | je                  0x12
            //   6a01                 | push                1

        $sequence_4 = { 3b9c24000d0000 0f84cc090000 8a8424f0020000 84c0 0f84bd090000 8a8424e8000000 84c0 }
            // n = 7, score = 200
            //   3b9c24000d0000       | cmp                 ebx, dword ptr [esp + 0xd00]
            //   0f84cc090000         | je                  0x9d2
            //   8a8424f0020000       | mov                 al, byte ptr [esp + 0x2f0]
            //   84c0                 | test                al, al
            //   0f84bd090000         | je                  0x9c3
            //   8a8424e8000000       | mov                 al, byte ptr [esp + 0xe8]
            //   84c0                 | test                al, al

        $sequence_5 = { 8bfd 83c9ff 33c0 8d9424ec010000 f2ae f7d1 2bf9 }
            // n = 7, score = 200
            //   8bfd                 | mov                 edi, ebp
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8d9424ec010000       | lea                 edx, [esp + 0x1ec]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   2bf9                 | sub                 edi, ecx

        $sequence_6 = { 8b15???????? 52 ffd3 892d???????? a1???????? 3bc5 7416 }
            // n = 7, score = 200
            //   8b15????????         |                     
            //   52                   | push                edx
            //   ffd3                 | call                ebx
            //   892d????????         |                     
            //   a1????????           |                     
            //   3bc5                 | cmp                 eax, ebp
            //   7416                 | je                  0x18

        $sequence_7 = { f3a5 8bcd 8d9424f4030000 83e103 f3a4 8dbc24f4040000 }
            // n = 6, score = 200
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8bcd                 | mov                 ecx, ebp
            //   8d9424f4030000       | lea                 edx, [esp + 0x3f4]
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8dbc24f4040000       | lea                 edi, [esp + 0x4f4]

        $sequence_8 = { 683f000f00 6a00 56 ff15???????? 8bf8 }
            // n = 5, score = 200
            //   683f000f00           | push                0xf003f
            //   6a00                 | push                0
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_9 = { 83c40c 85c0 0f85e00c0000 8b4b04 6a04 }
            // n = 5, score = 200
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   0f85e00c0000         | jne                 0xce6
            //   8b4b04               | mov                 ecx, dword ptr [ebx + 4]
            //   6a04                 | push                4

    condition:
        7 of them and filesize < 122880
}