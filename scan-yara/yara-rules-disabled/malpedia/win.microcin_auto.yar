rule win_microcin_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.microcin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.microcin"
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
        $sequence_0 = { 50 56 ff15???????? 85c0 0f45f7 }
            // n = 5, score = 400
            //   50                   | mov                 ecx, dword ptr [ebp - 4]
            //   56                   | mov                 eax, dword ptr [ebp + 0x10]
            //   ff15????????         |                     
            //   85c0                 | mov                 ecx, dword ptr [ebp + ecx*4 - 0x188]
            //   0f45f7               | mov                 dword ptr [eax + edx*4], ecx

        $sequence_1 = { 442bc3 4803d6 4533c9 ff15???????? 85c0 75d9 488b742438 }
            // n = 7, score = 400
            //   442bc3               | lea                 eax, [ebp - 0x108]
            //   4803d6               | push                0x104
            //   4533c9               | push                eax
            //   ff15????????         |                     
            //   85c0                 | lea                 eax, [ebp - 0x108]
            //   75d9                 | xor                 esi, esi
            //   488b742438           | push                eax

        $sequence_2 = { ff15???????? 488bcb ff15???????? 448bc0 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   488bcb               | call                ebx
            //   ff15????????         |                     
            //   448bc0               | test                eax, eax

        $sequence_3 = { 57 4154 4156 4157 488dac2400fbffff 4881ec00060000 488b05???????? }
            // n = 7, score = 400
            //   57                   | jle                 0x1f
            //   4154                 | cmp                 byte ptr [ebp + esi - 0x158], 0x3a
            //   4156                 | push                0x10
            //   4157                 | push                eax
            //   488dac2400fbffff     | push                esi
            //   4881ec00060000       | test                eax, eax
            //   488b05????????       |                     

        $sequence_4 = { e8???????? 83c40c 8d85f8feffff 6804010000 50 ff15???????? 8d85f8feffff }
            // n = 7, score = 400
            //   e8????????           |                     
            //   83c40c               | push                ebx
            //   8d85f8feffff         | dec                 eax
            //   6804010000           | sub                 esp, 0x20
            //   50                   | mov                 ebx, ecx
            //   ff15????????         |                     
            //   8d85f8feffff         | mov                 ecx, ebx

        $sequence_5 = { 488b09 418bf8 488bf2 33db }
            // n = 4, score = 400
            //   488b09               | cmovne              esi, edi
            //   418bf8               | push                eax
            //   488bf2               | push                0x1005
            //   33db                 | push                0xffff

        $sequence_6 = { ff15???????? 8b3d???????? 8d85e0feffff 50 }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   8b3d????????         |                     
            //   8d85e0feffff         | jmp                 0xffffffd4
            //   50                   | mov                 ebx, dword ptr [ebp - 0x30]

        $sequence_7 = { 488bcb 664489642438 488bf0 ff15???????? }
            // n = 4, score = 400
            //   488bcb               | add                 esp, 0xc
            //   664489642438         | mov                 eax, edi
            //   488bf0               | lea                 eax, [ebp - 0x108]
            //   ff15????????         |                     

        $sequence_8 = { 68ffff0000 56 8b35???????? ffd6 }
            // n = 4, score = 400
            //   68ffff0000           | add                 esp, 0xc
            //   56                   | lea                 eax, [ebp - 0x108]
            //   8b35????????         |                     
            //   ffd6                 | push                0x104

        $sequence_9 = { 85c0 7e18 80bc35a8feffff3a 741f 8d85a8feffff 46 50 }
            // n = 7, score = 400
            //   85c0                 | inc                 ecx
            //   7e18                 | mov                 eax, 0x12010
            //   80bc35a8feffff3a     | dec                 eax
            //   741f                 | mov                 ecx, ebp
            //   8d85a8feffff         | inc                 ecx
            //   46                   | lea                 edx, [eax + 1]
            //   50                   | inc                 eax

        $sequence_10 = { c6840d8002000033 488d8d80020000 ff15???????? 4863c8 c6840d8002000079 }
            // n = 5, score = 400
            //   c6840d8002000033     | push                esi
            //   488d8d80020000       | call                esi
            //   ff15????????         |                     
            //   4863c8               | push                4
            //   c6840d8002000079     | push                dword ptr [ebp - 0x2c]

        $sequence_11 = { ff15???????? 8b1d???????? 8d85a8feffff 50 ffd3 }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   8b1d????????         |                     
            //   8d85a8feffff         | push                0xa400
            //   50                   | push                0
            //   ffd3                 | mov                 ecx, dword ptr [ebp - 0x10]

        $sequence_12 = { ff15???????? 4863c8 c6840d7002000062 488d8d70020000 ff15???????? 4863c8 }
            // n = 6, score = 400
            //   ff15????????         |                     
            //   4863c8               | test                eax, eax
            //   c6840d7002000062     | jle                 0x1f
            //   488d8d70020000       | cmp                 byte ptr [ebp + esi - 0x158], 0x3a
            //   ff15????????         |                     
            //   4863c8               | je                  0x30

        $sequence_13 = { ff15???????? 85c0 7426 8b400c }
            // n = 4, score = 400
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7426                 | jle                 0x1c
            //   8b400c               | cmp                 byte ptr [ebp + esi - 0x158], 0x3a

        $sequence_14 = { 33f6 50 ffd3 85c0 7e18 }
            // n = 5, score = 400
            //   33f6                 | sub                 esp, 8
            //   50                   | mov                 dword ptr [ebp - 8], ecx
            //   ffd3                 | mov                 dword ptr [ebp - 4], 0xa400
            //   85c0                 | push                0x40
            //   7e18                 | push                0x1000

        $sequence_15 = { 488d4c2460 ff15???????? 4863c8 807c0c5f5c 7413 488d4c2460 ff15???????? }
            // n = 7, score = 400
            //   488d4c2460           | push                esi
            //   ff15????????         |                     
            //   4863c8               | lea                 eax, [ebp - 0x158]
            //   807c0c5f5c           | push                eax
            //   7413                 | call                ebx
            //   488d4c2460           | lea                 eax, [ebp - 0x108]
            //   ff15????????         |                     

        $sequence_16 = { 41bc14030000 4c8d0574130100 488bcd 418bd4 e8???????? 33c9 85c0 }
            // n = 7, score = 200
            //   41bc14030000         | xor                 eax, eax
            //   4c8d0574130100       | jbe                 0x4c
            //   488bcd               | dec                 ecx
            //   418bd4               | mov                 ecx, ebp
            //   e8????????           |                     
            //   33c9                 | dec                 esp
            //   85c0                 | lea                 eax, [0x112b7]

        $sequence_17 = { 83c108 51 ff15???????? 8b4dfc }
            // n = 4, score = 200
            //   83c108               | dec                 ecx
            //   51                   | mov                 eax, ebx
            //   ff15????????         |                     
            //   8b4dfc               | dec                 ecx

        $sequence_18 = { 7370 696465726167656e 742e 657865 }
            // n = 4, score = 200
            //   7370                 | dec                 esp
            //   696465726167656e     | lea                 eax, [0x1126c]
            //   742e                 | dec                 eax
            //   657865               | lea                 edx, [0x10c73]

        $sequence_19 = { 6e 6d 656e 7400 }
            // n = 4, score = 200
            //   6e                   | test                eax, eax
            //   6d                   | mov                 ebx, ecx
            //   656e                 | dec                 eax
            //   7400                 | lea                 ecx, [0x10c95]

        $sequence_20 = { 8b4510 8b8c8d78feffff 890c90 ebc8 e9???????? }
            // n = 5, score = 200
            //   8b4510               | mov                 ecx, esi
            //   8b8c8d78feffff       | call                eax
            //   890c90               | mov                 dword ptr [ebp + 0x118], eax
            //   ebc8                 | sub                 esp, 8
            //   e9????????           |                     

        $sequence_21 = { 7647 498bcd e8???????? 4c8d05b7120100 41b903000000 }
            // n = 5, score = 200
            //   7647                 | jne                 0x48
            //   498bcd               | dec                 esp
            //   e8????????           |                     
            //   4c8d05b7120100       | mov                 eax, ebx
            //   41b903000000         | dec                 eax

        $sequence_22 = { fa fa fa fa fa fa }
            // n = 6, score = 200
            //   fa                   | dec                 eax
            //   fa                   | sub                 esp, 0x20
            //   fa                   | mov                 ebx, ecx
            //   fa                   | dec                 eax
            //   fa                   | lea                 ecx, [0x10c95]
            //   fa                   | dec                 eax

        $sequence_23 = { 8b4df0 e8???????? 8d45f8 50 6a00 }
            // n = 5, score = 200
            //   8b4df0               | cli                 
            //   e8????????           |                     
            //   8d45f8               | outsb               dx, byte ptr [esi]
            //   50                   | insd                dword ptr es:[edi], dx
            //   6a00                 | outsb               dx, byte ptr gs:[esi]

        $sequence_24 = { 6828010000 8d85ccfeffff 6a00 50 }
            // n = 4, score = 200
            //   6828010000           | push                ebx
            //   8d85ccfeffff         | push                ebx
            //   6a00                 | push                esi
            //   50                   | inc                 ebx

        $sequence_25 = { 418d7c24e7 85c0 752a 4c8d0502130100 8bd7 498bcd }
            // n = 6, score = 200
            //   418d7c24e7           | inc                 ecx
            //   85c0                 | mov                 ecx, 3
            //   752a                 | jbe                 0x49
            //   4c8d0502130100       | dec                 ecx
            //   8bd7                 | mov                 ecx, ebp
            //   498bcd               | dec                 esp

        $sequence_26 = { 4c8d056c120100 498bd4 488bcd e8???????? 85c0 7541 4c8bc3 }
            // n = 7, score = 200
            //   4c8d056c120100       | dec                 eax
            //   498bd4               | lea                 edx, [0x10c73]
            //   488bcd               | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, eax
            //   7541                 | dec                 esp
            //   4c8bc3               | lea                 eax, [0x1126c]

        $sequence_27 = { 636373 7673 6873742e65 7865 }
            // n = 4, score = 200
            //   636373               | cli                 
            //   7673                 | cli                 
            //   6873742e65           | jbe                 0x6f
            //   7865                 | jb                  0x71

        $sequence_28 = { ff15???????? 8b45f4 8b4824 894dfc 8b55f4 83c208 }
            // n = 6, score = 200
            //   ff15????????         |                     
            //   8b45f4               | inc                 ebp
            //   8b4824               | sub                 ebx, dword ptr [ecx + esi - 0x2008]
            //   894dfc               | inc                 ebp
            //   8b55f4               | mov                 dword ptr [esp + 4], ebx
            //   83c208               | mov                 ecx, esi

        $sequence_29 = { 8945fc eb42 8b45f8 33d2 }
            // n = 4, score = 200
            //   8945fc               | je                  0xa
            //   eb42                 | mov                 eax, dword ptr [ecx + esi - 0x200c]
            //   8b45f8               | inc                 esp
            //   33d2                 | sub                 ebx, eax

        $sequence_30 = { 8bd9 488d0d950c0100 ff15???????? 4885c0 7419 488d15730c0100 488bc8 }
            // n = 7, score = 200
            //   8bd9                 | mov                 ebx, ecx
            //   488d0d950c0100       | dec                 eax
            //   ff15????????         |                     
            //   4885c0               | lea                 ecx, [0x10c95]
            //   7419                 | dec                 eax
            //   488d15730c0100       | test                eax, eax
            //   488bc8               | je                  0x1b

        $sequence_31 = { 488d15f8110100 41b810200100 488bcd e8???????? e9???????? 4533c9 4533c0 }
            // n = 7, score = 200
            //   488d15f8110100       | dec                 ecx
            //   41b810200100         | mov                 edx, esp
            //   488bcd               | dec                 eax
            //   e8????????           |                     
            //   e9????????           |                     
            //   4533c9               | mov                 ecx, ebp
            //   4533c0               | test                eax, eax

        $sequence_32 = { 8b8504ffffff 898574feffff 8b4d0c 8b91fc020000 8b4508 0390f0040000 8b4d10 }
            // n = 7, score = 200
            //   8b8504ffffff         | je                  5
            //   898574feffff         | outsb               dx, byte ptr [esi]
            //   8b4d0c               | jbe                 0x6b
            //   8b91fc020000         | jb                  0x73
            //   8b4508               | outsb               dx, byte ptr [esi]
            //   0390f0040000         | insd                dword ptr es:[edi], dx
            //   8b4d10               | outsb               dx, byte ptr gs:[esi]

        $sequence_33 = { 488bcd e8???????? 85c0 751a 488d15f8110100 41b810200100 }
            // n = 6, score = 200
            //   488bcd               | dec                 eax
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, ebp
            //   751a                 | inc                 ebp
            //   488d15f8110100       | xor                 ecx, ecx
            //   41b810200100         | inc                 ebp

        $sequence_34 = { 8b55fc 83c208 52 ff15???????? 8b45fc c7400421000000 }
            // n = 6, score = 200
            //   8b55fc               | dec                 eax
            //   83c208               | lea                 edx, [ebp + 0x10]
            //   52                   | nop                 
            //   ff15????????         |                     
            //   8b45fc               | mov                 edx, 0xc4b3c4b3
            //   c7400421000000       | mov                 ecx, dword ptr [esp + 8]

        $sequence_35 = { 33c9 4889742420 e8???????? cc 4c8d056c120100 }
            // n = 5, score = 200
            //   33c9                 | inc                 ecx
            //   4889742420           | lea                 edi, [esp - 0x19]
            //   e8????????           |                     
            //   cc                   | test                eax, eax
            //   4c8d056c120100       | jne                 0x2c

        $sequence_36 = { 83ec08 894df8 c745fc00a40000 6a40 6800100000 6800a40000 6a00 }
            // n = 7, score = 200
            //   83ec08               | cli                 
            //   894df8               | cli                 
            //   c745fc00a40000       | cli                 
            //   6a40                 | cli                 
            //   6800100000           | cli                 
            //   6800a40000           | cli                 
            //   6a00                 | cli                 

        $sequence_37 = { 49 53 53 56 43 }
            // n = 5, score = 200
            //   49                   | test                eax, eax
            //   53                   | jne                 0x124
            //   53                   | dec                 esp
            //   56                   | lea                 eax, [0x1126c]
            //   43                   | dec                 ecx

        $sequence_38 = { 8b4c2414 33cc e8???????? 8be5 5d c21000 57 }
            // n = 7, score = 100
            //   8b4c2414             | xor                 edx, edx
            //   33cc                 | mov                 ecx, 4
            //   e8????????           |                     
            //   8be5                 | div                 ecx
            //   5d                   | add                 ecx, 8
            //   c21000               | push                ecx
            //   57                   | mov                 ecx, dword ptr [ebp - 4]

        $sequence_39 = { 0115???????? 1515151503 1515151515 1515041515 1515050607 0809 }
            // n = 6, score = 100
            //   0115????????         |                     
            //   1515151503           | mov                 eax, dword ptr [ebp - 4]
            //   1515151515           | mov                 dword ptr [eax + 4], 0x21
            //   1515041515           | mov                 dword ptr [ebp - 4], eax
            //   1515050607           | jmp                 0x44
            //   0809                 | mov                 eax, dword ptr [ebp - 8]

        $sequence_40 = { 8d85e8feffff 50 ff95e4feffff 59 59 837d1c00 7513 }
            // n = 7, score = 100
            //   8d85e8feffff         | insd                dword ptr es:[edi], dx
            //   50                   | outsb               dx, byte ptr gs:[esi]
            //   ff95e4feffff         | je                  8
            //   59                   | jae                 0x72
            //   59                   | imul                esp, dword ptr [ebp + 0x72], 0x6e656761
            //   837d1c00             | je                  0x3a
            //   7513                 | js                  0x74

        $sequence_41 = { 8b8431f4dfffff 44 2bd8 45 2b9c31f8dfffff 45 895c2404 }
            // n = 7, score = 100
            //   8b8431f4dfffff       | push                esi
            //   44                   | inc                 ebx
            //   2bd8                 | jae                 0x72
            //   45                   | imul                esp, dword ptr [ebp + 0x72], 0x6e656761
            //   2b9c31f8dfffff       | je                  0x38
            //   45                   | js                  0x72
            //   895c2404             | jbe                 0x6b

        $sequence_42 = { 6a00 8d442448 50 ff15???????? 85c0 7420 }
            // n = 6, score = 100
            //   6a00                 | add                 edx, dword ptr [eax + 0x4f0]
            //   8d442448             | mov                 ecx, dword ptr [ebp + 0x10]
            //   50                   | mov                 dword ptr [ebp - 4], eax
            //   ff15????????         |                     
            //   85c0                 | jmp                 0x47
            //   7420                 | mov                 eax, dword ptr [ebp - 8]

        $sequence_43 = { 8b4c2408 49 8b542410 e8???????? 85c0 74db 89c0 }
            // n = 7, score = 100
            //   8b4c2408             | cli                 
            //   49                   | cli                 
            //   8b542410             | cli                 
            //   e8????????           |                     
            //   85c0                 | cli                 
            //   74db                 | cli                 
            //   89c0                 | cli                 

        $sequence_44 = { f7f7 8365ec00 85c0 0f8e94010000 8365f000 8b7e44 }
            // n = 6, score = 100
            //   f7f7                 | push                ebx
            //   8365ec00             | push                ebx
            //   85c0                 | push                esi
            //   0f8e94010000         | inc                 ebx
            //   8365f000             | jb                  0x71
            //   8b7e44               | outsb               dx, byte ptr [esi]

        $sequence_45 = { 89f1 48 8d5510 e8???????? 90 e8???????? bab3c4b3c4 }
            // n = 7, score = 100
            //   89f1                 | jb                  0x71
            //   48                   | outsb               dx, byte ptr [esi]
            //   8d5510               | insd                dword ptr es:[edi], dx
            //   e8????????           |                     
            //   90                   | outsb               dx, byte ptr gs:[esi]
            //   e8????????           |                     
            //   bab3c4b3c4           | je                  8

        $sequence_46 = { 6a00 8d85b0feffff 50 56 }
            // n = 4, score = 100
            //   6a00                 | mov                 dword ptr [ebp - 0x18c], eax
            //   8d85b0feffff         | mov                 ecx, dword ptr [ebp + 0xc]
            //   50                   | mov                 edx, dword ptr [ecx + 0x2fc]
            //   56                   | mov                 eax, dword ptr [ebp + 8]

        $sequence_47 = { 6a00 56 c785b4feffff00000000 ff15???????? 50 56 }
            // n = 6, score = 100
            //   6a00                 | xor                 edx, edx
            //   56                   | mov                 eax, dword ptr [ebp - 0xc]
            //   c785b4feffff00000000     | mov    ecx, dword ptr [eax + 0x24]
            //   ff15????????         |                     
            //   50                   | mov                 dword ptr [ebp - 4], ecx
            //   56                   | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_48 = { 8d44245c 50 ff15???????? 33c0 5f }
            // n = 5, score = 100
            //   8d44245c             | add                 edx, 8
            //   50                   | mov                 edx, dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   33c0                 | add                 edx, 8
            //   5f                   | push                edx

        $sequence_49 = { c744241030000000 c744241403000000 c7442418d0114000 c744241c00000000 c744242000000000 89742424 c744242800000000 }
            // n = 7, score = 100
            //   c744241030000000     | mov                 eax, dword ptr [ebp + 0x10]
            //   c744241403000000     | mov                 ecx, dword ptr [ebp + ecx*4 - 0x188]
            //   c7442418d0114000     | mov                 dword ptr [eax + edx*4], ecx
            //   c744241c00000000     | jmp                 0xffffffd4
            //   c744242000000000     | mov                 ebx, dword ptr [ebp - 0x30]
            //   89742424             | jmp                 0xffffffad
            //   c744242800000000     | mov                 dword ptr [ebp - 0x1c], 0x4060f0

    condition:
        7 of them and filesize < 417792
}