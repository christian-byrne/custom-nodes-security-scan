rule win_klrd_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.klrd."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.klrd"
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
        $sequence_0 = { 8d85fcefffff 50 e8???????? 59 50 }
            // n = 5, score = 100
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax

        $sequence_1 = { 8d85fcefffff 50 57 ff15???????? 57 ff15???????? }
            // n = 6, score = 100
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   ff15????????         |                     

        $sequence_2 = { e8???????? 59 50 8d85fcefffff 50 57 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   50                   | push                eax
            //   8d85fcefffff         | lea                 eax, [ebp - 0x1004]
            //   50                   | push                eax
            //   57                   | push                edi

        $sequence_3 = { 3c00 0f8485020000 3c03 0f847d020000 3c09 0f8475020000 3c08 }
            // n = 7, score = 100
            //   3c00                 | cmp                 al, 0
            //   0f8485020000         | je                  0x28b
            //   3c03                 | cmp                 al, 3
            //   0f847d020000         | je                  0x283
            //   3c09                 | cmp                 al, 9
            //   0f8475020000         | je                  0x27b
            //   3c08                 | cmp                 al, 8

        $sequence_4 = { c685c0fdffff00 68ff000000 6a00 8d85c1fdffff 50 e8???????? 83c40c }
            // n = 7, score = 100
            //   c685c0fdffff00       | mov                 byte ptr [ebp - 0x240], 0
            //   68ff000000           | push                0xff
            //   6a00                 | push                0
            //   8d85c1fdffff         | lea                 eax, [ebp - 0x23f]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_5 = { 59 59 ff7510 ff750c ff7508 ff35???????? ff15???????? }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   ff7510               | push                dword ptr [ebp + 0x10]
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff35????????         |                     
            //   ff15????????         |                     

        $sequence_6 = { ebcc 8a85e7feffff 8885acfcffff 80bdacfcffff08 742f }
            // n = 5, score = 100
            //   ebcc                 | jmp                 0xffffffce
            //   8a85e7feffff         | mov                 al, byte ptr [ebp - 0x119]
            //   8885acfcffff         | mov                 byte ptr [ebp - 0x354], al
            //   80bdacfcffff08       | cmp                 byte ptr [ebp - 0x354], 8
            //   742f                 | je                  0x31

        $sequence_7 = { 56 56 6a04 56 56 68000000c0 68???????? }
            // n = 7, score = 100
            //   56                   | push                esi
            //   56                   | push                esi
            //   6a04                 | push                4
            //   56                   | push                esi
            //   56                   | push                esi
            //   68000000c0           | push                0xc0000000
            //   68????????           |                     

        $sequence_8 = { 59 8d7dec f3a5 8b45ec 25ff000000 8885e7feffff 3c00 }
            // n = 7, score = 100
            //   59                   | pop                 ecx
            //   8d7dec               | lea                 edi, [ebp - 0x14]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   25ff000000           | and                 eax, 0xff
            //   8885e7feffff         | mov                 byte ptr [ebp - 0x119], al
            //   3c00                 | cmp                 al, 0

        $sequence_9 = { ffb5b0fcffff ff15???????? 8985c8feffff 83bdc8feffff00 7515 ff15???????? }
            // n = 6, score = 100
            //   ffb5b0fcffff         | push                dword ptr [ebp - 0x350]
            //   ff15????????         |                     
            //   8985c8feffff         | mov                 dword ptr [ebp - 0x138], eax
            //   83bdc8feffff00       | cmp                 dword ptr [ebp - 0x138], 0
            //   7515                 | jne                 0x17
            //   ff15????????         |                     

    condition:
        7 of them and filesize < 40960
}