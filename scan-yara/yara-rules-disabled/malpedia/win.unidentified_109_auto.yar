rule win_unidentified_109_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.unidentified_109."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_109"
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
        $sequence_0 = { 488d55df 488d4df7 4c8d45f7 e8???????? 8bf0 85c0 }
            // n = 6, score = 100
            //   488d55df             | rol                 ebx, 0xa
            //   488d4df7             | add                 eax, dword ptr [ecx + 0x38]
            //   4c8d45f7             | inc                 ecx
            //   e8????????           |                     
            //   8bf0                 | mov                 ecx, ecx
            //   85c0                 | inc                 esp

        $sequence_1 = { 7405 85db 0f44d8 0fb68fa2030000 0fbe45ab 3bc1 7e11 }
            // n = 7, score = 100
            //   7405                 | cmp                 dword ptr [eax], ebp
            //   85db                 | je                  0x2313
            //   0f44d8               | dec                 eax
            //   0fb68fa2030000       | mov                 ecx, dword ptr [ecx + 0x80]
            //   0fbe45ab             | inc                 ebp
            //   3bc1                 | movzx               ecx, cx
            //   7e11                 | xor                 eax, eax

        $sequence_2 = { e8???????? 488bcb e8???????? 488bdf 4885ff 75b5 488b742430 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488bcb               | mov                 edi, ecx
            //   e8????????           |                     
            //   488bdf               | dec                 eax
            //   4885ff               | lea                 ecx, [esp + 0x42]
            //   75b5                 | inc                 ebp
            //   488b742430           | mov                 eax, eax

        $sequence_3 = { 8b07 418b09 4883c704 4d8d4904 480fafcd 4803c8 418bc0 }
            // n = 7, score = 100
            //   8b07                 | movzx               eax, word ptr [ecx + 0x270]
            //   418b09               | test                al, 8
            //   4883c704             | jne                 0xd70
            //   4d8d4904             | or                  ax, 8
            //   480fafcd             | mov                 word ptr [ecx + 0x270], ax
            //   4803c8               | xor                 eax, eax
            //   418bc0               | ret                 

        $sequence_4 = { 2b8300010000 3bc5 7312 8bd5 488bcb e8???????? 85c0 }
            // n = 7, score = 100
            //   2b8300010000         | dec                 eax
            //   3bc5                 | test                eax, eax
            //   7312                 | je                  0x13d3
            //   8bd5                 | call                eax
            //   488bcb               | jmp                 0x13d8
            //   e8????????           |                     
            //   85c0                 | mov                 ecx, 0x40

        $sequence_5 = { 4c8b3a 4c8be1 4c8bea 488d4c2420 41b8a8040000 33d2 }
            // n = 6, score = 100
            //   4c8b3a               | cmp                 bx, bp
            //   4c8be1               | jae                 0x242
            //   4c8bea               | inc                 esp
            //   488d4c2420           | movzx               eax, bp
            //   41b8a8040000         | je                  0x3ac
            //   33d2                 | cmp                 dword ptr [ebp - 0x58], 0

        $sequence_6 = { 23c6 440bf0 8d040a 418bd3 4403f0 418bc3 c1c80b }
            // n = 7, score = 100
            //   23c6                 | arpl                word ptr [ebx + 0x34], ax
            //   440bf0               | dec                 ecx
            //   8d040a               | add                 edx, dword ptr [edi + 0x290]
            //   418bd3               | inc                 ecx
            //   4403f0               | add                 ebp, 4
            //   418bc3               | dec                 eax
            //   c1c80b               | mov                 eax, dword ptr [ebx]

        $sequence_7 = { eb77 418d41ff 4863c8 488d048f 33ff 4d8d048a }
            // n = 6, score = 100
            //   eb77                 | mov                 eax, ebp
            //   418d41ff             | dec                 eax
            //   4863c8               | arpl                ax, cx
            //   488d048f             | dec                 eax
            //   33ff                 | lea                 eax, [edx + ecx*4]
            //   4d8d048a             | dec                 eax

        $sequence_8 = { 0f8462020000 83b90001000000 7621 e8???????? 89834c020000 85c0 0f8550020000 }
            // n = 7, score = 100
            //   0f8462020000         | mov                 dword ptr [eax + 0x118], ecx
            //   83b90001000000       | inc                 ecx
            //   7621                 | cmp                 esp, 1
            //   e8????????           |                     
            //   89834c020000         | jne                 0x9ed
            //   85c0                 | dec                 eax
            //   0f8550020000         | test                edi, edi

        $sequence_9 = { 4289449efc 4c3bdd 7c8b 8b442450 8b0b 4c8b742420 8903 }
            // n = 7, score = 100
            //   4289449efc           | dec                 esp
            //   4c3bdd               | mov                 edx, dword ptr [esp + 0x40]
            //   7c8b                 | inc                 esp
            //   8b442450             | add                 ecx, eax
            //   8b0b                 | inc                 ecx
            //   4c8b742420           | mov                 eax, eax
            //   8903                 | inc                 ecx

    condition:
        7 of them and filesize < 723968
}