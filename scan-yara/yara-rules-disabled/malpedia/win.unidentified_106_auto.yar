rule win_unidentified_106_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_106."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_106"
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
        $sequence_0 = { 8bc2 3bd5 7d14 2bea 33d2 448bc5 49c1e002 }
            // n = 7, score = 100
            //   8bc2                 | dec                 eax
            //   3bd5                 | mov                 edi, edx
            //   7d14                 | inc                 ecx
            //   2bea                 | movzx               esi, ax
            //   33d2                 | inc                 ecx
            //   448bc5               | movzx               edx, cx
            //   49c1e002             | dec                 eax

        $sequence_1 = { d0250000ffff 3d00000d00 740e 8b4b04 53 e8???????? 413bc7 }
            // n = 7, score = 100
            //   d0250000ffff         | jne                 0x4a4
            //   3d00000d00           | test                eax, eax
            //   740e                 | js                  0x42b
            //   8b4b04               | jmp                 0x4c4
            //   53                   | inc                 ecx
            //   e8????????           |                     
            //   413bc7               | mov                 eax, eax

        $sequence_2 = { e8???????? 488b8bf8000000 4889bbf0000000 e8???????? 488b8b00010000 4889bbf8000000 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b8bf8000000       | dec                 eax
            //   4889bbf0000000       | test                ecx, ecx
            //   e8????????           |                     
            //   488b8b00010000       | je                  0xc65
            //   4889bbf8000000       | dec                 eax
            //   e8????????           |                     

        $sequence_3 = { e8???????? e8???????? 8bc8 b881808080 f7e9 03d1 c1fa07 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   e8????????           |                     
            //   8bc8                 | jmp                 0x1018
            //   b881808080           | cmp                 ecx, 1
            //   f7e9                 | jne                 0x1aaa
            //   03d1                 | movzx               eax, word ptr [ebx + 0x30c]
            //   c1fa07               | inc                 ebp

        $sequence_4 = { 8bc1 418d140e 4803c6 41b800100000 66440b833c040000 4889442438 8bc2 }
            // n = 7, score = 100
            //   8bc1                 | inc                 ecx
            //   418d140e             | cmp                 eax, 0x2f1
            //   4803c6               | ja                  0xe02
            //   41b800100000         | push                edi
            //   66440b833c040000     | dec                 eax
            //   4889442438           | sub                 esp, 0x20
            //   8bc2                 | xor                 ebx, ebx

        $sequence_5 = { a806 0f85cf020000 bafbff0000 6623c2 6683c802 66898108030000 33c0 }
            // n = 7, score = 100
            //   a806                 | mov                 byte ptr [ebp + 0x4c], 1
            //   0f85cf020000         | jmp                 0x612
            //   bafbff0000           | je                  0x611
            //   6623c2               | dec                 eax
            //   6683c802             | cmp                 dword ptr [esi], 0
            //   66898108030000       | je                  0x115c
            //   33c0                 | inc                 ecx

        $sequence_6 = { 488d442448 4889442428 4c8bcb 488d442430 418bd7 498bce 4889442420 }
            // n = 7, score = 100
            //   488d442448           | je                  0x127
            //   4889442428           | mov                 eax, 0xfffffeaa
            //   4c8bcb               | jmp                 0x14f
            //   488d442430           | dec                 esp
            //   418bd7               | mov                 eax, dword ptr [esp + 0x88]
            //   498bce               | inc                 esp
            //   4889442420           | mov                 ecx, ebx

        $sequence_7 = { e8???????? 85c0 7920 488b0f 488d5710 4885d2 0f8454fbffff }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | jne                 0x7e1
            //   7920                 | inc                 ecx
            //   488b0f               | lea                 eax, [edi - 0x7d]
            //   488d5710             | cmp                 ecx, 0x4001
            //   4885d2               | mov                 ecx, 0x4100
            //   0f8454fbffff         | inc                 ecx

        $sequence_8 = { e9???????? 498b5f08 be02000000 440fb7f5 4d03f3 4180fc06 7508 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   498b5f08             | test                eax, eax
            //   be02000000           | test                eax, eax
            //   440fb7f5             | jne                 0x14a3
            //   4d03f3               | mov                 ecx, dword ptr [ebx + 0x178]
            //   4180fc06             | lea                 edx, [esi + 4]
            //   7508                 | dec                 eax

        $sequence_9 = { 90 eb02 eb00 498bc4 488b5c2478 488bac2480000000 4883c440 }
            // n = 7, score = 100
            //   90                   | add                 edx, ecx
            //   eb02                 | inc                 esp
            //   eb00                 | mov                 eax, ebp
            //   498bc4               | dec                 ecx
            //   488b5c2478           | mov                 ecx, edi
            //   488bac2480000000     | mov                 eax, ebp
            //   4883c440             | jae                 0x143b

    condition:
        7 of them and filesize < 27402240
}