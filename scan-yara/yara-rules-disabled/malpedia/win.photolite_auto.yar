rule win_photolite_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.photolite."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.photolite"
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
        $sequence_0 = { c7859802000042cc7257 c7859c02000075cc545d c785a002000040c02638 8b8594020000 8a8590020000 84c0 751e }
            // n = 7, score = 400
            //   c7859802000042cc7257     | dec    eax
            //   c7859c02000075cc545d     | mov    edi, dword ptr [esp + 0x30]
            //   c785a002000040c02638     | jmp    0xffffffaa
            //   8b8594020000         | dec                 eax
            //   8a8590020000         | mov                 ebx, dword ptr [esp + 0x48]
            //   84c0                 | mov                 dword ptr [ebp + 0x594], 0x3a3af437
            //   751e                 | mov                 dword ptr [ebp + 0x598], 0x1c39ef2f

        $sequence_1 = { ff15???????? 498bd6 488d4d76 ff15???????? 8a4301 }
            // n = 5, score = 400
            //   ff15????????         |                     
            //   498bd6               | mov                 al, byte ptr [ebp + 0x2e0]
            //   488d4d76             | test                al, al
            //   ff15????????         |                     
            //   8a4301               | jne                 0x22

        $sequence_2 = { c7859405000037f43a3a c785980500002fef391c c7859c0500000be1241d c785a00500002fe54a79 8b8590050000 8a858c050000 84c0 }
            // n = 7, score = 400
            //   c7859405000037f43a3a     | dec    ebp
            //   c785980500002fef391c     | add    ecx, edx
            //   c7859c0500000be1241d     | test    edx, edx
            //   c785a00500002fe54a79     | je    0x76
            //   8b8590050000         | inc                 esp
            //   8a858c050000         | mov                 eax, eax
            //   84c0                 | jae                 9

        $sequence_3 = { 8a85e0020000 84c0 751e 488bcb 8b848de4020000 }
            // n = 5, score = 400
            //   8a85e0020000         | cmp                 ecx, esi
            //   84c0                 | jb                  0xffffffe7
            //   751e                 | mov                 byte ptr [esp + 0x4c], bl
            //   488bcb               | mov                 dword ptr [esp + 0x50], 0x106c1057
            //   8b848de4020000       | mov                 dword ptr [esp + 0x54], 0x304c6a55

        $sequence_4 = { 4803cf 483bce 72e5 885c244c c744245057106c10 c7442454556a4c30 }
            // n = 6, score = 400
            //   4803cf               | sub                 eax, esi
            //   483bce               | dec                 eax
            //   72e5                 | sub                 eax, edi
            //   885c244c             | dec                 eax
            //   c744245057106c10     | add                 ecx, edi
            //   c7442454556a4c30     | dec                 eax

        $sequence_5 = { 8bc3 4d03ca 85d2 7474 448bc0 }
            // n = 5, score = 400
            //   8bc3                 | dec                 eax
            //   4d03ca               | mov                 ecx, ebx
            //   85d2                 | mov                 eax, dword ptr [ebp + ecx*4 + 0x2e4]
            //   7474                 | dec                 ecx
            //   448bc0               | mov                 edx, esi

        $sequence_6 = { 7421 0f1002 488bc2 482bc6 482bc7 }
            // n = 5, score = 400
            //   7421                 | je                  0x23
            //   0f1002               | movups              xmm0, xmmword ptr [edx]
            //   488bc2               | dec                 eax
            //   482bc6               | mov                 eax, edx
            //   482bc7               | dec                 eax

        $sequence_7 = { 7307 488b7c2430 eba3 488b5c2448 }
            // n = 4, score = 400
            //   7307                 | dec                 eax
            //   488b7c2430           | lea                 ecx, [ebp + 0x76]
            //   eba3                 | mov                 al, byte ptr [ebx + 1]
            //   488b5c2448           | mov                 eax, ebx

        $sequence_8 = { 48895d38 48895da0 895d30 488b01 ff5070 8bf8 85c0 }
            // n = 7, score = 100
            //   48895d38             | test                al, al
            //   48895da0             | jne                 0x22
            //   895d30               | dec                 eax
            //   488b01               | mov                 ecx, ebx
            //   ff5070               | mov                 eax, dword ptr [ebp + ecx*4 + 0x2e4]
            //   8bf8                 | dec                 ecx
            //   85c0                 | mov                 edx, esi

        $sequence_9 = { 488bd8 4885c0 0f8419010000 488b15???????? }
            // n = 4, score = 100
            //   488bd8               | mov                 al, byte ptr [ebp + 0x290]
            //   4885c0               | test                al, al
            //   0f8419010000         | jne                 0x4c
            //   488b15????????       |                     

        $sequence_10 = { 488bcb ffd0 ffc6 41b8bb010000 8bd6 }
            // n = 5, score = 100
            //   488bcb               | dec                 eax
            //   ffd0                 | mov                 edi, dword ptr [esp + 0x30]
            //   ffc6                 | jmp                 0xffffffac
            //   41b8bb010000         | dec                 eax
            //   8bd6                 | mov                 ebx, dword ptr [esp + 0x48]

        $sequence_11 = { 84c0 0f85f5000000 4885db 7451 488b05???????? 4885c0 7426 }
            // n = 7, score = 100
            //   84c0                 | mov                 dword ptr [ebp + 0x594], 0x3a3af437
            //   0f85f5000000         | mov                 dword ptr [ebp + 0x598], 0x1c39ef2f
            //   4885db               | mov                 dword ptr [ebp + 0x59c], 0x1d24e10b
            //   7451                 | mov                 dword ptr [ebp + 0x5a0], 0x794ae52f
            //   488b05????????       |                     
            //   4885c0               | mov                 eax, dword ptr [ebp + 0x590]
            //   7426                 | mov                 al, byte ptr [ebp + 0x58c]

        $sequence_12 = { 72e9 4c8d442444 41b901000000 488d047e 410fb6d1 }
            // n = 5, score = 100
            //   72e9                 | test                al, al
            //   4c8d442444           | mov                 dword ptr [ebp + 0x298], 0x5772cc42
            //   41b901000000         | mov                 dword ptr [ebp + 0x29c], 0x5d54cc75
            //   488d047e             | mov                 dword ptr [ebp + 0x2a0], 0x3826c040
            //   410fb6d1             | mov                 eax, dword ptr [ebp + 0x294]

        $sequence_13 = { 3dc8000000 0f849d000000 488b5d28 4885db }
            // n = 4, score = 100
            //   3dc8000000           | mov                 eax, ebx
            //   0f849d000000         | dec                 ebp
            //   488b5d28             | add                 ecx, edx
            //   4885db               | test                edx, edx

        $sequence_14 = { 75f2 33db 4084f6 0f84e6000000 }
            // n = 4, score = 100
            //   75f2                 | je                  0x7d
            //   33db                 | inc                 esp
            //   4084f6               | mov                 eax, eax
            //   0f84e6000000         | jae                 9

        $sequence_15 = { 488d542474 488d8de0020000 ff15???????? 408874245c }
            // n = 4, score = 100
            //   488d542474           | dec                 eax
            //   488d8de0020000       | lea                 ecx, [ebp + 0x76]
            //   ff15????????         |                     
            //   408874245c           | mov                 al, byte ptr [ebx + 1]

    condition:
        7 of them and filesize < 99328
}