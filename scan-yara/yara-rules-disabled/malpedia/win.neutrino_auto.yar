rule win_neutrino_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.neutrino."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neutrino"
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
        $sequence_0 = { ff15???????? c1e010 50 ff15???????? }
            // n = 4, score = 2300
            //   ff15????????         |                     
            //   c1e010               | shl                 eax, 0x10
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_1 = { 50 6a0b 6a07 e8???????? }
            // n = 4, score = 1600
            //   50                   | push                eax
            //   6a0b                 | push                0xb
            //   6a07                 | push                7
            //   e8????????           |                     

        $sequence_2 = { 50 6a05 6a03 e8???????? }
            // n = 4, score = 1600
            //   50                   | push                eax
            //   6a05                 | push                5
            //   6a03                 | push                3
            //   e8????????           |                     

        $sequence_3 = { 85c9 7439 8b550c 8955fc 8b45fc 0fbe08 85c9 }
            // n = 7, score = 1500
            //   85c9                 | test                ecx, ecx
            //   7439                 | je                  0x3b
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]
            //   8955fc               | mov                 dword ptr [ebp - 4], edx
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fbe08               | movsx               ecx, byte ptr [eax]
            //   85c9                 | test                ecx, ecx

        $sequence_4 = { 0fbe02 85c0 7447 8b4df4 0fbe11 8b45fc 0fbe08 }
            // n = 7, score = 1500
            //   0fbe02               | movsx               eax, byte ptr [edx]
            //   85c0                 | test                eax, eax
            //   7447                 | je                  0x49
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   0fbe11               | movsx               edx, byte ptr [ecx]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fbe08               | movsx               ecx, byte ptr [eax]

        $sequence_5 = { 0404 0404 0404 0402 0202 0202 }
            // n = 6, score = 1500
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0402                 | add                 al, 2
            //   0202                 | add                 al, byte ptr [edx]
            //   0202                 | add                 al, byte ptr [edx]

        $sequence_6 = { 8b4d0c 894dfc 8b55f4 83c201 8955f4 ebaf 8b45f4 }
            // n = 7, score = 1500
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]
            //   83c201               | add                 edx, 1
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   ebaf                 | jmp                 0xffffffb1
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_7 = { 0404 0404 010404 0202 }
            // n = 4, score = 1500
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   010404               | add                 dword ptr [esp + eax], eax
            //   0202                 | add                 al, byte ptr [edx]

        $sequence_8 = { 020402 0404 0404 0404 0404 0404 0403 }
            // n = 7, score = 1500
            //   020402               | add                 al, byte ptr [edx + eax]
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0404                 | add                 al, 4
            //   0403                 | add                 al, 3

        $sequence_9 = { 51 0fb655e7 52 8b45e0 50 e8???????? }
            // n = 6, score = 1500
            //   51                   | push                ecx
            //   0fb655e7             | movzx               edx, byte ptr [ebp - 0x19]
            //   52                   | push                edx
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_10 = { 0fbe08 85c9 741b 8b55fc 0fbe02 8b4df8 0fbe11 }
            // n = 7, score = 1500
            //   0fbe08               | movsx               ecx, byte ptr [eax]
            //   85c9                 | test                ecx, ecx
            //   741b                 | je                  0x1d
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   0fbe02               | movsx               eax, byte ptr [edx]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   0fbe11               | movsx               edx, byte ptr [ecx]

        $sequence_11 = { 894dfc 8b55fc 0fbe02 85c0 750f 8b4d0c 894dfc }
            // n = 7, score = 1500
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   0fbe02               | movsx               eax, byte ptr [edx]
            //   85c0                 | test                eax, eax
            //   750f                 | jne                 0x11
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx

        $sequence_12 = { 6a00 ff15???????? 6880000000 ff15???????? }
            // n = 4, score = 1500
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   6880000000           | push                0x80
            //   ff15????????         |                     

        $sequence_13 = { 010404 0202 020402 0404 }
            // n = 4, score = 1500
            //   010404               | add                 dword ptr [esp + eax], eax
            //   0202                 | add                 al, byte ptr [edx]
            //   020402               | add                 al, byte ptr [edx + eax]
            //   0404                 | add                 al, 4

        $sequence_14 = { e9???????? 6a01 ff15???????? 85c0 }
            // n = 4, score = 1500
            //   e9????????           |                     
            //   6a01                 | push                1
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax

        $sequence_15 = { 52 ff15???????? 83f8ff 7504 32c0 eb02 b001 }
            // n = 7, score = 1500
            //   52                   | push                edx
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   7504                 | jne                 6
            //   32c0                 | xor                 al, al
            //   eb02                 | jmp                 4
            //   b001                 | mov                 al, 1

        $sequence_16 = { 894d08 0fb6550c 83fa01 7509 8b4508 83c001 894508 }
            // n = 7, score = 1500
            //   894d08               | mov                 dword ptr [ebp + 8], ecx
            //   0fb6550c             | movzx               edx, byte ptr [ebp + 0xc]
            //   83fa01               | cmp                 edx, 1
            //   7509                 | jne                 0xb
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c001               | add                 eax, 1
            //   894508               | mov                 dword ptr [ebp + 8], eax

        $sequence_17 = { 7407 814a1800300000 f645fe01 0f8494020000 834a1801 8b45f4 }
            // n = 6, score = 1300
            //   7407                 | je                  9
            //   814a1800300000       | or                  dword ptr [edx + 0x18], 0x3000
            //   f645fe01             | test                byte ptr [ebp - 2], 1
            //   0f8494020000         | je                  0x29a
            //   834a1801             | or                  dword ptr [edx + 0x18], 1
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]

        $sequence_18 = { 6a1c 5b 8d4de0 51 50 895de0 ff15???????? }
            // n = 7, score = 1300
            //   6a1c                 | push                0x1c
            //   5b                   | pop                 ebx
            //   8d4de0               | lea                 ecx, [ebp - 0x20]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   895de0               | mov                 dword ptr [ebp - 0x20], ebx
            //   ff15????????         |                     

        $sequence_19 = { 8a00 ff45f4 8b7218 8ad8 c0eb06 885dfc }
            // n = 6, score = 1300
            //   8a00                 | mov                 al, byte ptr [eax]
            //   ff45f4               | inc                 dword ptr [ebp - 0xc]
            //   8b7218               | mov                 esi, dword ptr [edx + 0x18]
            //   8ad8                 | mov                 bl, al
            //   c0eb06               | shr                 bl, 6
            //   885dfc               | mov                 byte ptr [ebp - 4], bl

        $sequence_20 = { 7354 8b3b 0fb6f2 6a05 58 2bc6 8d1437 }
            // n = 7, score = 1300
            //   7354                 | jae                 0x56
            //   8b3b                 | mov                 edi, dword ptr [ebx]
            //   0fb6f2               | movzx               esi, dl
            //   6a05                 | push                5
            //   58                   | pop                 eax
            //   2bc6                 | sub                 eax, esi
            //   8d1437               | lea                 edx, [edi + esi]

        $sequence_21 = { 51 ff35???????? c7460480000000 ff15???????? 8906 }
            // n = 5, score = 1300
            //   51                   | push                ecx
            //   ff35????????         |                     
            //   c7460480000000       | mov                 dword ptr [esi + 4], 0x80
            //   ff15????????         |                     
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_22 = { 33d2 81e100f0ffff eb08 3bc1 7409 8bd0 }
            // n = 6, score = 1300
            //   33d2                 | xor                 edx, edx
            //   81e100f0ffff         | and                 ecx, 0xfffff000
            //   eb08                 | jmp                 0xa
            //   3bc1                 | cmp                 eax, ecx
            //   7409                 | je                  0xb
            //   8bd0                 | mov                 edx, eax

        $sequence_23 = { f645fe02 740a 834a1804 8a03 884210 43 f645fe40 }
            // n = 7, score = 1300
            //   f645fe02             | test                byte ptr [ebp - 2], 2
            //   740a                 | je                  0xc
            //   834a1804             | or                  dword ptr [edx + 0x18], 4
            //   8a03                 | mov                 al, byte ptr [ebx]
            //   884210               | mov                 byte ptr [edx + 0x10], al
            //   43                   | inc                 ebx
            //   f645fe40             | test                byte ptr [ebp - 2], 0x40

        $sequence_24 = { 83c120 81fae00f0000 76ea 8b0d???????? 8908 a3???????? 5f }
            // n = 7, score = 1300
            //   83c120               | add                 ecx, 0x20
            //   81fae00f0000         | cmp                 edx, 0xfe0
            //   76ea                 | jbe                 0xffffffec
            //   8b0d????????         |                     
            //   8908                 | mov                 dword ptr [eax], ecx
            //   a3????????           |                     
            //   5f                   | pop                 edi

        $sequence_25 = { 8d85b8feffff 50 68???????? ff15???????? 8945fc }
            // n = 5, score = 1100
            //   8d85b8feffff         | lea                 eax, [ebp - 0x148]
            //   50                   | push                eax
            //   68????????           |                     
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_26 = { 83c40c 6804010000 8d85f8fdffff 50 }
            // n = 4, score = 1000
            //   83c40c               | add                 esp, 0xc
            //   6804010000           | push                0x104
            //   8d85f8fdffff         | lea                 eax, [ebp - 0x208]
            //   50                   | push                eax

        $sequence_27 = { 7507 68???????? eb05 68???????? 50 ff510c }
            // n = 6, score = 800
            //   7507                 | jne                 9
            //   68????????           |                     
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   50                   | push                eax
            //   ff510c               | call                dword ptr [ecx + 0xc]

        $sequence_28 = { 7522 be???????? ff15???????? 57 8906 ff15???????? 83c604 }
            // n = 7, score = 800
            //   7522                 | jne                 0x24
            //   be????????           |                     
            //   ff15????????         |                     
            //   57                   | push                edi
            //   8906                 | mov                 dword ptr [esi], eax
            //   ff15????????         |                     
            //   83c604               | add                 esi, 4

        $sequence_29 = { 7412 68???????? 50 ff15???????? f7d8 1bc0 }
            // n = 6, score = 800
            //   7412                 | je                  0x14
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   f7d8                 | neg                 eax
            //   1bc0                 | sbb                 eax, eax

        $sequence_30 = { 57 33ff 393d???????? 7522 be???????? }
            // n = 5, score = 800
            //   57                   | push                edi
            //   33ff                 | xor                 edi, edi
            //   393d????????         |                     
            //   7522                 | jne                 0x24
            //   be????????           |                     

        $sequence_31 = { ff15???????? 50 ff15???????? 837dfc00 0f95c0 c9 }
            // n = 6, score = 800
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0
            //   0f95c0               | setne               al
            //   c9                   | leave               

        $sequence_32 = { ff750c ff7508 ff15???????? 83f8ff 0f95c0 }
            // n = 5, score = 800
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   0f95c0               | setne               al

    condition:
        7 of them and filesize < 507904
}