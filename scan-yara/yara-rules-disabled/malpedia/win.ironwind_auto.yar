rule win_ironwind_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ironwind."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ironwind"
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
        $sequence_0 = { be01000000 8bc6 e9???????? 4803c9 488b6cca08 4885ed 74e7 }
            // n = 7, score = 100
            //   be01000000           | jmp                 0x1020
            //   8bc6                 | dec                 esp
            //   e9????????           |                     
            //   4803c9               | mov                 ebp, dword ptr [esp + 0x20]
            //   488b6cca08           | dec                 eax
            //   4885ed               | test                ebx, ebx
            //   74e7                 | je                  0x106b

        $sequence_1 = { c3 4533c0 418d5002 8d4a15 ff15???????? 4883f8ff }
            // n = 6, score = 100
            //   c3                   | dec                 ecx
            //   4533c0               | mov                 ecx, edi
            //   418d5002             | test                eax, eax
            //   8d4a15               | jne                 0x111a
            //   ff15????????         |                     
            //   4883f8ff             | cmp                 byte ptr [edi + 0x1300], al

        $sequence_2 = { e9???????? 488d0d823e0300 4889bc24a0000000 e8???????? 488bf8 4885c0 7508 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   488d0d823e0300       | je                  0x714
            //   4889bc24a0000000     | dec                 ebp
            //   e8????????           |                     
            //   488bf8               | lea                 esi, [eax + 1]
            //   4885c0               | dec                 esp
            //   7508                 | add                 esi, edi

        $sequence_3 = { ff15???????? 488b742460 4885db 7409 488bcb ff15???????? 8bc7 }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   488b742460           | cmp                 al, 0x39
            //   4885db               | jle                 0x75
            //   7409                 | dec                 eax
            //   488bcb               | cmp                 ecx, edi
            //   ff15????????         |                     
            //   8bc7                 | jae                 0x9b

        $sequence_4 = { 80b85011000001 488d152cc40400 488d0d4dc40400 480f45d1 488bc8 e8???????? 488bf8 }
            // n = 7, score = 100
            //   80b85011000001       | mov                 eax, edi
            //   488d152cc40400       | dec                 eax
            //   488d0d4dc40400       | mov                 ebx, dword ptr [esp + 0x48]
            //   480f45d1             | dec                 eax
            //   488bc8               | mov                 ebp, dword ptr [esp + 0x50]
            //   e8????????           |                     
            //   488bf8               | dec                 eax

        $sequence_5 = { 8d5001 8d4838 ff15???????? 488bf8 4885c0 7508 8d471b }
            // n = 7, score = 100
            //   8d5001               | lea                 ecx, [0x36b4e]
            //   8d4838               | test                eax, eax
            //   ff15????????         |                     
            //   488bf8               | jne                 0xa4e
            //   4885c0               | mov                 eax, 0x6603
            //   7508                 | dec                 eax
            //   8d471b               | lea                 edx, [ebp - 0x30]

        $sequence_6 = { f20f1101 e9???????? 0f57c0 f2480f2a87100b0000 f20f1101 e9???????? 0f57c0 }
            // n = 7, score = 100
            //   f20f1101             | cmove               bx, dx
            //   e9????????           |                     
            //   0f57c0               | dec                 eax
            //   f2480f2a87100b0000     | mov    eax, dword ptr [esp + 0x60]
            //   f20f1101             | inc                 esi
            //   e9????????           |                     
            //   0f57c0               | inc                 ecx

        $sequence_7 = { bf05000000 8bc7 eb53 bf02000000 8bc7 eb4a 664183f804 }
            // n = 7, score = 100
            //   bf05000000           | mov                 eax, dword ptr [ebp - 0x48]
            //   8bc7                 | dec                 esp
            //   eb53                 | cmovne              esp, dword ptr [ebp - 0x78]
            //   bf02000000           | dec                 eax
            //   8bc7                 | mov                 dword ptr [esp + 0x68], eax
            //   eb4a                 | dec                 ecx
            //   664183f804           | cmovne              eax, esp

        $sequence_8 = { 85c0 742e 0fbe03 4c8d156f8ffdff 83c0e0 83f85a 0f8765020000 }
            // n = 7, score = 100
            //   85c0                 | dec                 eax
            //   742e                 | lea                 eax, [0x37c7a]
            //   0fbe03               | ret                 
            //   4c8d156f8ffdff       | dec                 eax
            //   83c0e0               | lea                 eax, [0x37c92]
            //   83f85a               | dec                 eax
            //   0f8765020000         | lea                 eax, [0x37f32]

        $sequence_9 = { e8???????? 488b8f50070000 4885c9 7469 ff15???????? 488983d0060000 4885c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488b8f50070000       | dec                 ecx
            //   4885c9               | mov                 ecx, edi
            //   7469                 | dec                 ecx
            //   ff15????????         |                     
            //   488983d0060000       | mov                 ecx, esp
            //   4885c0               | mov                 edi, eax

    condition:
        7 of them and filesize < 995328
}