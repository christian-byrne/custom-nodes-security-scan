rule win_romeos_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.romeos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.romeos"
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
        $sequence_0 = { 750a 5e 33c0 5b 83c408 c20c00 8b06 }
            // n = 7, score = 400
            //   750a                 | jne                 0xc
            //   5e                   | pop                 esi
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   83c408               | add                 esp, 8
            //   c20c00               | ret                 0xc
            //   8b06                 | mov                 eax, dword ptr [esi]

        $sequence_1 = { bd30000000 33db 85ed 7e0e e8???????? 88441c18 43 }
            // n = 7, score = 400
            //   bd30000000           | mov                 ebp, 0x30
            //   33db                 | xor                 ebx, ebx
            //   85ed                 | test                ebp, ebp
            //   7e0e                 | jle                 0x10
            //   e8????????           |                     
            //   88441c18             | mov                 byte ptr [esp + ebx + 0x18], al
            //   43                   | inc                 ebx

        $sequence_2 = { 6a16 8d4c244c 6800200000 51 57 }
            // n = 5, score = 400
            //   6a16                 | push                0x16
            //   8d4c244c             | lea                 ecx, [esp + 0x4c]
            //   6800200000           | push                0x2000
            //   51                   | push                ecx
            //   57                   | push                edi

        $sequence_3 = { 83ec08 53 56 8b742418 8bd9 85f6 750a }
            // n = 7, score = 400
            //   83ec08               | sub                 esp, 8
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]
            //   8bd9                 | mov                 ebx, ecx
            //   85f6                 | test                esi, esi
            //   750a                 | jne                 0xc

        $sequence_4 = { 5f 5e 5d 5b 81c438200000 c20400 }
            // n = 6, score = 400
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx
            //   81c438200000         | add                 esp, 0x2038
            //   c20400               | ret                 4

        $sequence_5 = { 8b542408 668902 b001 c3 668b4801 40 51 }
            // n = 7, score = 400
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   668902               | mov                 word ptr [edx], ax
            //   b001                 | mov                 al, 1
            //   c3                   | ret                 
            //   668b4801             | mov                 cx, word ptr [eax + 1]
            //   40                   | inc                 eax
            //   51                   | push                ecx

        $sequence_6 = { 85db 751d 807c244802 0f85e0000000 8d542414 8d442448 }
            // n = 6, score = 400
            //   85db                 | test                ebx, ebx
            //   751d                 | jne                 0x1f
            //   807c244802           | cmp                 byte ptr [esp + 0x48], 2
            //   0f85e0000000         | jne                 0xe6
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   8d442448             | lea                 eax, [esp + 0x48]

        $sequence_7 = { 6a16 8d44244c 52 50 }
            // n = 4, score = 400
            //   6a16                 | push                0x16
            //   8d44244c             | lea                 eax, [esp + 0x4c]
            //   52                   | push                edx
            //   50                   | push                eax

        $sequence_8 = { 68bb010000 8b39 50 ff15???????? 8b8e20030000 50 53 }
            // n = 7, score = 200
            //   68bb010000           | push                0x1bb
            //   8b39                 | mov                 edi, dword ptr [ecx]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b8e20030000         | mov                 ecx, dword ptr [esi + 0x320]
            //   50                   | push                eax
            //   53                   | push                ebx

        $sequence_9 = { e8???????? 8bf0 eb02 33f6 53 6800040000 8d4c243c }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4
            //   33f6                 | xor                 esi, esi
            //   53                   | push                ebx
            //   6800040000           | push                0x400
            //   8d4c243c             | lea                 ecx, [esp + 0x3c]

        $sequence_10 = { 50 8bce e8???????? 8d8c2490010000 51 }
            // n = 5, score = 200
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8d8c2490010000       | lea                 ecx, [esp + 0x190]
            //   51                   | push                ecx

        $sequence_11 = { 81c428010000 c3 5f 5e 5d 83c8ff 5b }
            // n = 7, score = 200
            //   81c428010000         | add                 esp, 0x128
            //   c3                   | ret                 
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   83c8ff               | or                  eax, 0xffffffff
            //   5b                   | pop                 ebx

        $sequence_12 = { 8bf1 57 b940000000 33c0 8d7c2415 c644241400 c744240800000000 }
            // n = 7, score = 200
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   b940000000           | mov                 ecx, 0x40
            //   33c0                 | xor                 eax, eax
            //   8d7c2415             | lea                 edi, [esp + 0x15]
            //   c644241400           | mov                 byte ptr [esp + 0x14], 0
            //   c744240800000000     | mov                 dword ptr [esp + 8], 0

        $sequence_13 = { 895c2440 895c2434 895c2438 ff15???????? }
            // n = 4, score = 200
            //   895c2440             | mov                 dword ptr [esp + 0x40], ebx
            //   895c2434             | mov                 dword ptr [esp + 0x34], ebx
            //   895c2438             | mov                 dword ptr [esp + 0x38], ebx
            //   ff15????????         |                     

        $sequence_14 = { 8b442410 85c0 7408 66837c241400 7510 47 }
            // n = 6, score = 200
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   66837c241400         | cmp                 word ptr [esp + 0x14], 0
            //   7510                 | jne                 0x12
            //   47                   | inc                 edi

        $sequence_15 = { 8b3a eb0d 8b8e20030000 68bb010000 }
            // n = 4, score = 200
            //   8b3a                 | mov                 edi, dword ptr [edx]
            //   eb0d                 | jmp                 0xf
            //   8b8e20030000         | mov                 ecx, dword ptr [esi + 0x320]
            //   68bb010000           | push                0x1bb

    condition:
        7 of them and filesize < 294912
}