rule win_ozone_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ozone"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { 80780c00 7407 8b06 e8???????? }
            // n = 4, score = 300
            //   80780c00             | cmp                 byte ptr [eax + 0xc], 0
            //   7407                 | je                  9
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   e8????????           |                     

        $sequence_1 = { 807a0c00 7410 8bd4 8bc8 }
            // n = 4, score = 300
            //   807a0c00             | cmp                 byte ptr [edx + 0xc], 0
            //   7410                 | je                  0x12
            //   8bd4                 | mov                 edx, esp
            //   8bc8                 | mov                 ecx, eax

        $sequence_2 = { 8bde 8b03 a3???????? 8d45fc }
            // n = 4, score = 300
            //   8bde                 | mov                 ebx, esi
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   a3????????           |                     
            //   8d45fc               | lea                 eax, [ebp - 4]

        $sequence_3 = { 893a 39d7 7517 bafeffffff d3c2 21148520e74000 7507 }
            // n = 7, score = 300
            //   893a                 | mov                 dword ptr [edx], edi
            //   39d7                 | cmp                 edi, edx
            //   7517                 | jne                 0x19
            //   bafeffffff           | mov                 edx, 0xfffffffe
            //   d3c2                 | rol                 edx, cl
            //   21148520e74000       | and                 dword ptr [eax*4 + 0x40e720], edx
            //   7507                 | jne                 9

        $sequence_4 = { 5d 5f 5e 5b c3 53 66833d????????00 }
            // n = 7, score = 300
            //   5d                   | pop                 ebp
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx
            //   c3                   | ret                 
            //   53                   | push                ebx
            //   66833d????????00     |                     

        $sequence_5 = { 0fb6c3 0fb69830d74000 0fb6c3 8bd6 e8???????? 5e }
            // n = 6, score = 300
            //   0fb6c3               | movzx               eax, bl
            //   0fb69830d74000       | movzx               ebx, byte ptr [eax + 0x40d730]
            //   0fb6c3               | movzx               eax, bl
            //   8bd6                 | mov                 edx, esi
            //   e8????????           |                     
            //   5e                   | pop                 esi

        $sequence_6 = { 0fbfd3 8882402b4100 43 663b5c2402 7522 66b80200 }
            // n = 6, score = 300
            //   0fbfd3               | movsx               edx, bx
            //   8882402b4100         | mov                 byte ptr [edx + 0x412b40], al
            //   43                   | inc                 ebx
            //   663b5c2402           | cmp                 bx, word ptr [esp + 2]
            //   7522                 | jne                 0x24
            //   66b80200             | mov                 ax, 2

        $sequence_7 = { 21049520e74000 7507 0fb315???????? bff0ffffff }
            // n = 4, score = 300
            //   21049520e74000       | and                 dword ptr [edx*4 + 0x40e720], eax
            //   7507                 | jne                 9
            //   0fb315????????       |                     
            //   bff0ffffff           | mov                 edi, 0xfffffff0

        $sequence_8 = { 0000 43 6f 6e 6e }
            // n = 5, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   43                   | inc                 ebx
            //   6f                   | outsd               dx, dword ptr [esi]
            //   6e                   | outsb               dx, byte ptr [esi]
            //   6e                   | outsb               dx, byte ptr [esi]

        $sequence_9 = { 0010 af 45 00d0 }
            // n = 4, score = 100
            //   0010                 | add                 byte ptr [eax], dl
            //   af                   | scasd               eax, dword ptr es:[edi]
            //   45                   | inc                 ebp
            //   00d0                 | add                 al, dl

        $sequence_10 = { 0004f9 45 0030 07 }
            // n = 4, score = 100
            //   0004f9               | add                 byte ptr [ecx + edi*8], al
            //   45                   | inc                 ebp
            //   0030                 | add                 byte ptr [eax], dh
            //   07                   | pop                 es

        $sequence_11 = { 0000 53 8bd8 8bc3 e8???????? 6a00 }
            // n = 6, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   53                   | push                ebx
            //   8bd8                 | mov                 ebx, eax
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   6a00                 | push                0

        $sequence_12 = { 0000 00832d440373 0001 0f8395000000 }
            // n = 4, score = 100
            //   0000                 | add                 byte ptr [eax], al
            //   00832d440373         | add                 byte ptr [ebx + 0x7303442d], al
            //   0001                 | add                 byte ptr [ecx], al
            //   0f8395000000         | jae                 0x9b

        $sequence_13 = { 0001 0f8395000000 68???????? e8???????? }
            // n = 4, score = 100
            //   0001                 | add                 byte ptr [ecx], al
            //   0f8395000000         | jae                 0x9b
            //   68????????           |                     
            //   e8????????           |                     

        $sequence_14 = { 0008 56 46 002cc1 }
            // n = 4, score = 100
            //   0008                 | add                 byte ptr [eax], cl
            //   56                   | push                esi
            //   46                   | inc                 esi
            //   002cc1               | add                 byte ptr [ecx + eax*8], ch

        $sequence_15 = { 0007 11544375 7374 6f }
            // n = 4, score = 100
            //   0007                 | add                 byte ptr [edi], al
            //   11544375             | adc                 dword ptr [ebx + eax*2 + 0x75], edx
            //   7374                 | jae                 0x76
            //   6f                   | outsd               dx, dword ptr [esi]

    condition:
        7 of them and filesize < 65175552
}