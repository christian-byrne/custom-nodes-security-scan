rule win_mbrlock_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mbrlock."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mbrlock"
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
        $sequence_0 = { 898e94000000 8945e4 e9???????? 8b5d10 8b7d14 8b4e0c }
            // n = 6, score = 100
            //   898e94000000         | mov                 dword ptr [esi + 0x94], ecx
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   e9????????           |                     
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8b7d14               | mov                 edi, dword ptr [ebp + 0x14]
            //   8b4e0c               | mov                 ecx, dword ptr [esi + 0xc]

        $sequence_1 = { 8bcb bd01000000 e8???????? 8bf0 85f6 0f84f8000000 85ed }
            // n = 7, score = 100
            //   8bcb                 | mov                 ecx, ebx
            //   bd01000000           | mov                 ebp, 1
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   0f84f8000000         | je                  0xfe
            //   85ed                 | test                ebp, ebp

        $sequence_2 = { 8b4de8 8bc1 25ffff0000 2d4c450000 7475 83e802 7433 }
            // n = 7, score = 100
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8bc1                 | mov                 eax, ecx
            //   25ffff0000           | and                 eax, 0xffff
            //   2d4c450000           | sub                 eax, 0x454c
            //   7475                 | je                  0x77
            //   83e802               | sub                 eax, 2
            //   7433                 | je                  0x35

        $sequence_3 = { e8???????? 8b45ec 3d00800000 74ab 8b450c 8d5594 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   3d00800000           | cmp                 eax, 0x8000
            //   74ab                 | je                  0xffffffad
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8d5594               | lea                 edx, [ebp - 0x6c]

        $sequence_4 = { 894e30 50 53 8bcf e8???????? 85c0 7505 }
            // n = 7, score = 100
            //   894e30               | mov                 dword ptr [esi + 0x30], ecx
            //   50                   | push                eax
            //   53                   | push                ebx
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7

        $sequence_5 = { e8???????? 8bd0 85d2 7424 817f1402000080 7519 8b470c }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8bd0                 | mov                 edx, eax
            //   85d2                 | test                edx, edx
            //   7424                 | je                  0x26
            //   817f1402000080       | cmp                 dword ptr [edi + 0x14], 0x80000002
            //   7519                 | jne                 0x1b
            //   8b470c               | mov                 eax, dword ptr [edi + 0xc]

        $sequence_6 = { 8bcf e8???????? 8b4d08 894144 8b45ec 85c0 7505 }
            // n = 7, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   894144               | mov                 dword ptr [ecx + 0x44], eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7

        $sequence_7 = { 33d2 8bd9 668b144590844a00 8b4c2430 8954242c 8bc1 be02000000 }
            // n = 7, score = 100
            //   33d2                 | xor                 edx, edx
            //   8bd9                 | mov                 ebx, ecx
            //   668b144590844a00     | mov                 dx, word ptr [eax*2 + 0x4a8490]
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]
            //   8954242c             | mov                 dword ptr [esp + 0x2c], edx
            //   8bc1                 | mov                 eax, ecx
            //   be02000000           | mov                 esi, 2

        $sequence_8 = { 68ac5e0110 56 50 53 8bcf e8???????? }
            // n = 6, score = 100
            //   68ac5e0110           | push                0x10015eac
            //   56                   | push                esi
            //   50                   | push                eax
            //   53                   | push                ebx
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_9 = { a3???????? 39a81c010000 7405 8b4010 eb02 33c0 ffd0 }
            // n = 7, score = 100
            //   a3????????           |                     
            //   39a81c010000         | cmp                 dword ptr [eax + 0x11c], ebp
            //   7405                 | je                  7
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   eb02                 | jmp                 4
            //   33c0                 | xor                 eax, eax
            //   ffd0                 | call                eax

    condition:
        7 of them and filesize < 2031616
}