rule win_icedid_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.icedid."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid"
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
        $sequence_0 = { 85c0 7511 56 57 ff15???????? }
            // n = 5, score = 1300
            //   85c0                 | test                eax, eax
            //   7511                 | jne                 0x13
            //   56                   | push                esi
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_1 = { 50 6801000080 ff15???????? eb13 }
            // n = 4, score = 1300
            //   50                   | push                eax
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     
            //   eb13                 | jmp                 0x15

        $sequence_2 = { 803e00 7427 6a3b 56 ff15???????? 8bf8 }
            // n = 6, score = 1300
            //   803e00               | cmp                 byte ptr [esi], 0
            //   7427                 | je                  0x29
            //   6a3b                 | push                0x3b
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_3 = { ff15???????? 85c0 7420 837c241000 7419 }
            // n = 5, score = 1300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7420                 | je                  0x22
            //   837c241000           | cmp                 dword ptr [esp + 0x10], 0
            //   7419                 | je                  0x1b

        $sequence_4 = { 56 ff15???????? 8bf8 85ff 7418 c60700 }
            // n = 6, score = 1300
            //   56                   | push                esi
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   7418                 | je                  0x1a
            //   c60700               | mov                 byte ptr [edi], 0

        $sequence_5 = { 68???????? 6a00 ff15???????? 33c0 40 }
            // n = 5, score = 1300
            //   68????????           |                     
            //   6a00                 | push                0
            //   ff15????????         |                     
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_6 = { 50 ff15???????? 8bf7 8bc6 eb02 }
            // n = 5, score = 1300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8bf7                 | mov                 esi, edi
            //   8bc6                 | mov                 eax, esi
            //   eb02                 | jmp                 4

        $sequence_7 = { eb0f 6a08 ff15???????? 50 ff15???????? 8906 }
            // n = 6, score = 1300
            //   eb0f                 | jmp                 0x11
            //   6a08                 | push                8
            //   ff15????????         |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8906                 | mov                 dword ptr [esi], eax

        $sequence_8 = { e8???????? 8bf0 8d45fc 50 ff75fc 6a05 }
            // n = 6, score = 1000
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   6a05                 | push                5

        $sequence_9 = { 743f 8d5808 0fb713 8954241c }
            // n = 4, score = 800
            //   743f                 | je                  0x41
            //   8d5808               | lea                 ebx, [eax + 8]
            //   0fb713               | movzx               edx, word ptr [ebx]
            //   8954241c             | mov                 dword ptr [esp + 0x1c], edx

        $sequence_10 = { 03c2 eb5c 8d5004 89542414 8b12 85d2 }
            // n = 6, score = 800
            //   03c2                 | add                 eax, edx
            //   eb5c                 | jmp                 0x5e
            //   8d5004               | lea                 edx, [eax + 4]
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   85d2                 | test                edx, edx

        $sequence_11 = { 66c16c241c0c 0fb7d2 c744241000100000 663b542410 }
            // n = 4, score = 800
            //   66c16c241c0c         | shr                 word ptr [esp + 0x1c], 0xc
            //   0fb7d2               | movzx               edx, dx
            //   c744241000100000     | mov                 dword ptr [esp + 0x10], 0x1000
            //   663b542410           | cmp                 dx, word ptr [esp + 0x10]

        $sequence_12 = { 47 83c302 3bfd 72c4 }
            // n = 4, score = 800
            //   47                   | inc                 edi
            //   83c302               | add                 ebx, 2
            //   3bfd                 | cmp                 edi, ebp
            //   72c4                 | jb                  0xffffffc6

        $sequence_13 = { 8d4508 50 0fb6440b34 50 }
            // n = 4, score = 800
            //   8d4508               | lea                 eax, [ebp + 8]
            //   50                   | push                eax
            //   0fb6440b34           | movzx               eax, byte ptr [ebx + ecx + 0x34]
            //   50                   | push                eax

        $sequence_14 = { 89542414 8b12 85d2 7454 8d6af8 d1ed }
            // n = 6, score = 800
            //   89542414             | mov                 dword ptr [esp + 0x14], edx
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   85d2                 | test                edx, edx
            //   7454                 | je                  0x56
            //   8d6af8               | lea                 ebp, [edx - 8]
            //   d1ed                 | shr                 ebp, 1

        $sequence_15 = { 47 3b7820 72d1 5b 33c0 40 }
            // n = 6, score = 800
            //   47                   | inc                 edi
            //   3b7820               | cmp                 edi, dword ptr [eax + 0x20]
            //   72d1                 | jb                  0xffffffd3
            //   5b                   | pop                 ebx
            //   33c0                 | xor                 eax, eax
            //   40                   | inc                 eax

        $sequence_16 = { ff5010 85c0 7407 33c0 e9???????? }
            // n = 5, score = 400
            //   ff5010               | call                dword ptr [eax + 0x10]
            //   85c0                 | test                eax, eax
            //   7407                 | je                  9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     

        $sequence_17 = { 8a4173 a808 75f5 a804 7406 }
            // n = 5, score = 400
            //   8a4173               | mov                 al, byte ptr [ecx + 0x73]
            //   a808                 | test                al, 8
            //   75f5                 | jne                 0xfffffff7
            //   a804                 | test                al, 4
            //   7406                 | je                  8

        $sequence_18 = { ff15???????? 85c0 750a b8010000c0 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   b8010000c0           | mov                 eax, 0xc0000001

        $sequence_19 = { 41 02fd c6430503 eb21 41 0fb6c1 }
            // n = 6, score = 200
            //   41                   | inc                 ecx
            //   02fd                 | add                 bh, ch
            //   c6430503             | mov                 byte ptr [ebx + 5], 3
            //   eb21                 | jmp                 0x23
            //   41                   | inc                 ecx
            //   0fb6c1               | movzx               eax, cl

        $sequence_20 = { 48 8bfa 48 8bf1 45 8d41ce e8???????? }
            // n = 7, score = 200
            //   48                   | dec                 eax
            //   8bfa                 | mov                 edi, edx
            //   48                   | dec                 eax
            //   8bf1                 | mov                 esi, ecx
            //   45                   | inc                 ebp
            //   8d41ce               | lea                 eax, [ecx - 0x32]
            //   e8????????           |                     

        $sequence_21 = { 7407 41 2bcd 7515 eb0f 44 }
            // n = 6, score = 200
            //   7407                 | je                  9
            //   41                   | inc                 ecx
            //   2bcd                 | sub                 ecx, ebp
            //   7515                 | jne                 0x17
            //   eb0f                 | jmp                 0x11
            //   44                   | inc                 esp

        $sequence_22 = { 48 8d442458 48 8bf9 48 }
            // n = 5, score = 200
            //   48                   | dec                 eax
            //   8d442458             | lea                 eax, [esp + 0x58]
            //   48                   | dec                 eax
            //   8bf9                 | mov                 edi, ecx
            //   48                   | dec                 eax

        $sequence_23 = { 8bce 894348 48 8b15???????? }
            // n = 4, score = 200
            //   8bce                 | mov                 ecx, esi
            //   894348               | mov                 dword ptr [ebx + 0x48], eax
            //   48                   | dec                 eax
            //   8b15????????         |                     

        $sequence_24 = { 7307 4c8b742420 eba1 488bb590020000 }
            // n = 4, score = 100
            //   7307                 | mov                 ecx, eax
            //   4c8b742420           | dec                 eax
            //   eba1                 | mov                 esi, dword ptr [ebp + 0x290]
            //   488bb590020000       | dec                 eax

        $sequence_25 = { 57 4883ec30 488bf2 488bd9 ff15???????? 4885c0 }
            // n = 6, score = 100
            //   57                   | dec                 ebp
            //   4883ec30             | mov                 esi, eax
            //   488bf2               | dec                 eax
            //   488bd9               | and                 dword ptr [eax - 0x28], edi
            //   ff15????????         |                     
            //   4885c0               | dec                 esp

        $sequence_26 = { 7409 8b4c2478 493b0e 741e 498b1f 4885db }
            // n = 6, score = 100
            //   7409                 | je                  0xb
            //   8b4c2478             | mov                 ecx, dword ptr [esp + 0x78]
            //   493b0e               | dec                 ecx
            //   741e                 | cmp                 ecx, dword ptr [esi]
            //   498b1f               | je                  0x20
            //   4885db               | dec                 ecx

        $sequence_27 = { 33d2 488bc8 ff15???????? 488bb590020000 4885f6 7414 ff15???????? }
            // n = 7, score = 100
            //   33d2                 | mov                 ebx, dword ptr [edi]
            //   488bc8               | dec                 eax
            //   ff15????????         |                     
            //   488bb590020000       | test                ebx, ebx
            //   4885f6               | xor                 edx, edx
            //   7414                 | dec                 eax
            //   ff15????????         |                     

        $sequence_28 = { 33d2 488bce ff15???????? 8bd8 49891e 85c0 }
            // n = 6, score = 100
            //   33d2                 | mov                 esi, eax
            //   488bce               | dec                 eax
            //   ff15????????         |                     
            //   8bd8                 | cmp                 eax, -1
            //   49891e               | jne                 0x10
            //   85c0                 | push                edi

        $sequence_29 = { 4533c0 c740c803000000 ba00000080 ff15???????? 488bf0 4883f8ff 7507 }
            // n = 7, score = 100
            //   4533c0               | mov                 esi, dword ptr [ebp + 0x290]
            //   c740c803000000       | pop                 ebp
            //   ba00000080           | ret                 
            //   ff15????????         |                     
            //   488bf0               | dec                 eax
            //   4883f8ff             | lea                 eax, [0x1e0d]
            //   7507                 | xor                 edi, edi

        $sequence_30 = { 33ff 4d8bf0 482178d8 4c8bfa }
            // n = 4, score = 100
            //   33ff                 | dec                 esp
            //   4d8bf0               | mov                 esi, dword ptr [esp + 0x20]
            //   482178d8             | jmp                 0xffffffaa
            //   4c8bfa               | dec                 eax

        $sequence_31 = { 5d c3 488b0d???????? 488d050d1e0000 }
            // n = 4, score = 100
            //   5d                   | test                esi, esi
            //   c3                   | je                  0x16
            //   488b0d????????       |                     
            //   488d050d1e0000       | jae                 9

    condition:
        7 of them and filesize < 303104
}