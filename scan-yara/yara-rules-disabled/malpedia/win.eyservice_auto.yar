rule win_eyservice_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.eyservice."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eyservice"
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
        $sequence_0 = { c1f802 3bf0 72da eb22 8b0d???????? 2b0d???????? c1f902 }
            // n = 7, score = 100
            //   c1f802               | sar                 eax, 2
            //   3bf0                 | cmp                 esi, eax
            //   72da                 | jb                  0xffffffdc
            //   eb22                 | jmp                 0x24
            //   8b0d????????         |                     
            //   2b0d????????         |                     
            //   c1f902               | sar                 ecx, 2

        $sequence_1 = { 6a01 6a01 68???????? ffd6 83c410 8d542410 52 }
            // n = 7, score = 100
            //   6a01                 | push                1
            //   6a01                 | push                1
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c410               | add                 esp, 0x10
            //   8d542410             | lea                 edx, [esp + 0x10]
            //   52                   | push                edx

        $sequence_2 = { 83bef800000000 747c 8d4c2408 e8???????? a1???????? 8d4c2408 51 }
            // n = 7, score = 100
            //   83bef800000000       | cmp                 dword ptr [esi + 0xf8], 0
            //   747c                 | je                  0x7e
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   e8????????           |                     
            //   a1????????           |                     
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   51                   | push                ecx

        $sequence_3 = { 6808020000 8d8e34020000 51 e8???????? 85c0 7c1e }
            // n = 6, score = 100
            //   6808020000           | push                0x208
            //   8d8e34020000         | lea                 ecx, [esi + 0x234]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7c1e                 | jl                  0x20

        $sequence_4 = { 83c404 8bc8 e8???????? 8bf0 8bce e8???????? 8b4f10 }
            // n = 7, score = 100
            //   83c404               | add                 esp, 4
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8b4f10               | mov                 ecx, dword ptr [edi + 0x10]

        $sequence_5 = { e8???????? b901000000 66894f08 5f 5e 5d 8d410d }
            // n = 7, score = 100
            //   e8????????           |                     
            //   b901000000           | mov                 ecx, 1
            //   66894f08             | mov                 word ptr [edi + 8], cx
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   8d410d               | lea                 eax, [ecx + 0xd]

        $sequence_6 = { 68???????? 8d542418 52 ff15???????? 85c0 754f 88442414 }
            // n = 7, score = 100
            //   68????????           |                     
            //   8d542418             | lea                 edx, [esp + 0x18]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   754f                 | jne                 0x51
            //   88442414             | mov                 byte ptr [esp + 0x14], al

        $sequence_7 = { 50 03f7 56 e8???????? 8b4c2420 83c410 5f }
            // n = 7, score = 100
            //   50                   | push                eax
            //   03f7                 | add                 esi, edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   83c410               | add                 esp, 0x10
            //   5f                   | pop                 edi

        $sequence_8 = { a3???????? e8???????? 6a06 68???????? 56 a3???????? }
            // n = 6, score = 100
            //   a3????????           |                     
            //   e8????????           |                     
            //   6a06                 | push                6
            //   68????????           |                     
            //   56                   | push                esi
            //   a3????????           |                     

        $sequence_9 = { 85c0 7459 66837d005c 7452 66837c24145c 754a }
            // n = 6, score = 100
            //   85c0                 | test                eax, eax
            //   7459                 | je                  0x5b
            //   66837d005c           | cmp                 word ptr [ebp], 0x5c
            //   7452                 | je                  0x54
            //   66837c24145c         | cmp                 word ptr [esp + 0x14], 0x5c
            //   754a                 | jne                 0x4c

    condition:
        7 of them and filesize < 452608
}