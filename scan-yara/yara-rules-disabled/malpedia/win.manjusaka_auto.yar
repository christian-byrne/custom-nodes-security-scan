rule win_manjusaka_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.manjusaka."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.manjusaka"
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
        $sequence_0 = { ebb8 488d05b77a1000 4889442450 48c744245801000000 48c744246000000000 488d05f9b01100 4889442470 }
            // n = 7, score = 100
            //   ebb8                 | lea                 edx, [eax + 2]
            //   488d05b77a1000       | dec                 ebp
            //   4889442450           | mov                 eax, edi
            //   48c744245801000000     | dec    eax
            //   48c744246000000000     | mov    ecx, ebx
            //   488d05f9b01100       | mov                 edx, 3
            //   4889442470           | dec                 eax

        $sequence_1 = { 4c89bc2480040000 4c8939 4c897108 48895910 48c7411800800000 0f117018 48897930 }
            // n = 7, score = 100
            //   4c89bc2480040000     | lea                 ecx, [esp + 0x28]
            //   4c8939               | dec                 eax
            //   4c897108             | mov                 dword ptr [ecx], eax
            //   48895910             | dec                 eax
            //   48c7411800800000     | lea                 edx, [esp + 0x58]
            //   0f117018             | dec                 eax
            //   48897930             | mov                 dword ptr [edx], eax

        $sequence_2 = { 791d 418b4128 41034124 4863c8 488bc2 48f7d8 48c1e00a }
            // n = 7, score = 100
            //   791d                 | dec                 ebp
            //   418b4128             | arpl                word ptr [edi + 0x40], cx
            //   41034124             | inc                 ecx
            //   4863c8               | mov                 dword ptr [edi + 0x38], eax
            //   488bc2               | mov                 al, byte ptr [edx + 0x42]
            //   48f7d8               | neg                 al
            //   48c1e00a             | sbb                 cl, cl

        $sequence_3 = { 89411c 488b45d7 2b4527 05feffff07 89710c 894120 8b45db }
            // n = 7, score = 100
            //   89411c               | movaps              xmmword ptr [ebp + 0x810], xmm6
            //   488b45d7             | inc                 ecx
            //   2b4527               | mov                 eax, 0x3c0
            //   05feffff07           | dec                 eax
            //   89710c               | lea                 ecx, [ebp + 0x820]
            //   894120               | dec                 eax
            //   8b45db               | lea                 edx, [ebp + 0x3c0]

        $sequence_4 = { 4989f8 e8???????? 48ffcb 75ed 0f57f6 488d9c2410010000 0f297320 }
            // n = 7, score = 100
            //   4989f8               | mov                 ecx, dword ptr [edi + esi + 0x18]
            //   e8????????           |                     
            //   48ffcb               | dec                 eax
            //   75ed                 | mov                 edx, edi
            //   0f57f6               | dec                 ecx
            //   488d9c2410010000     | mov                 ecx, esp
            //   0f297320             | inc                 ebp

        $sequence_5 = { 898c24f8000000 48896c2448 3b08 0f8c21fdffff 4c8bbc24f0000000 4d85f6 7424 }
            // n = 7, score = 100
            //   898c24f8000000       | mov                 dword ptr [eax], ebx
            //   48896c2448           | mov                 byte ptr [eax + 8], 1
            //   3b08                 | dec                 eax
            //   0f8c21fdffff         | test                edi, edi
            //   4c8bbc24f0000000     | je                  0x311
            //   4d85f6               | mov                 word ptr [ebx + 0xa6], ax
            //   7424                 | dec                 esp

        $sequence_6 = { 814d4002020000 4533c0 48894500 498bcd 83c8ff 66894544 b8c8000000 }
            // n = 7, score = 100
            //   814d4002020000       | je                  0xe5
            //   4533c0               | dec                 ebp
            //   48894500             | mov                 ebp, eax
            //   498bcd               | mov                 edx, 6
            //   83c8ff               | dec                 eax
            //   66894544             | mov                 dword ptr [esp + 0x38], eax
            //   b8c8000000           | dec                 ecx

        $sequence_7 = { 89573c 48894740 895750 488b442e60 48894758 488b442e28 488b4860 }
            // n = 7, score = 100
            //   89573c               | test                bx, bx
            //   48894740             | jne                 0x849
            //   895750               | dec                 esp
            //   488b442e60           | cmp                 ecx, eax
            //   48894758             | je                  0x8ef
            //   488b442e28           | test                dx, dx
            //   488b4860             | je                  0xa0d

        $sequence_8 = { f7d8 894c2420 448bc5 498bcd 1bd2 4533c9 83e2fc }
            // n = 7, score = 100
            //   f7d8                 | je                  0x2024
            //   894c2420             | mov                 edx, 0x1a0
            //   448bc5               | mov                 dword ptr [esi + 0x18], edi
            //   498bcd               | mov                 dword ptr [esi + 0x1c], eax
            //   1bd2                 | mov                 dword ptr [esi + 0x20], eax
            //   4533c9               | dec                 eax
            //   83e2fc               | mov                 edi, eax

        $sequence_9 = { e8???????? 4889d9 e8???????? 488d4f70 e8???????? 488d8fe0000000 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   4889d9               | mov                 dword ptr [ebx + 0x10], eax
            //   e8????????           |                     
            //   488d4f70             | mov                 dword ptr [ebx + 4], eax
            //   e8????????           |                     
            //   488d8fe0000000       | or                  eax, 0xffffffff
            //   e8????????           |                     

    condition:
        7 of them and filesize < 4772864
}