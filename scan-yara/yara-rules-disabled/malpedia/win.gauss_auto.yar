rule win_gauss_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.gauss."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gauss"
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
        $sequence_0 = { e8???????? 894508 8945ec c645fc01 }
            // n = 4, score = 700
            //   e8????????           |                     
            //   894508               | mov                 dword ptr [ebp + 8], eax
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1

        $sequence_1 = { 57 8965f0 8b7508 e8???????? }
            // n = 4, score = 700
            //   57                   | push                edi
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   e8????????           |                     

        $sequence_2 = { 33db 895de4 66895dd4 895dfc }
            // n = 4, score = 700
            //   33db                 | xor                 ebx, ebx
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   66895dd4             | mov                 word ptr [ebp - 0x2c], bx
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx

        $sequence_3 = { 56 e8???????? 8bb080000000 e8???????? 8b4c2408 898880000000 8bc6 }
            // n = 7, score = 700
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bb080000000         | mov                 esi, dword ptr [eax + 0x80]
            //   e8????????           |                     
            //   8b4c2408             | mov                 ecx, dword ptr [esp + 8]
            //   898880000000         | mov                 dword ptr [eax + 0x80], ecx
            //   8bc6                 | mov                 eax, esi

        $sequence_4 = { c706???????? c744241000000000 837e2410 720c }
            // n = 4, score = 600
            //   c706????????         |                     
            //   c744241000000000     | mov                 dword ptr [esp + 0x10], 0
            //   837e2410             | cmp                 dword ptr [esi + 0x24], 0x10
            //   720c                 | jb                  0xe

        $sequence_5 = { 8bf1 50 8975f0 e8???????? 8365fc00 c706???????? 834dfcff }
            // n = 7, score = 600
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   c706????????         |                     
            //   834dfcff             | or                  dword ptr [ebp - 4], 0xffffffff

        $sequence_6 = { 83f808 7205 8b7604 eb03 83c604 66832600 33c0 }
            // n = 7, score = 600
            //   83f808               | cmp                 eax, 8
            //   7205                 | jb                  7
            //   8b7604               | mov                 esi, dword ptr [esi + 4]
            //   eb03                 | jmp                 5
            //   83c604               | add                 esi, 4
            //   66832600             | and                 word ptr [esi], 0
            //   33c0                 | xor                 eax, eax

        $sequence_7 = { 83c404 c746240f000000 c7462000000000 c6461000 c7442410ffffffff 8bce }
            // n = 6, score = 600
            //   83c404               | add                 esp, 4
            //   c746240f000000       | mov                 dword ptr [esi + 0x24], 0xf
            //   c7462000000000       | mov                 dword ptr [esi + 0x20], 0
            //   c6461000             | mov                 byte ptr [esi + 0x10], 0
            //   c7442410ffffffff     | mov                 dword ptr [esp + 0x10], 0xffffffff
            //   8bce                 | mov                 ecx, esi

        $sequence_8 = { 57 56 e8???????? eb18 85ff 7514 217e14 }
            // n = 7, score = 600
            //   57                   | push                edi
            //   56                   | push                esi
            //   e8????????           |                     
            //   eb18                 | jmp                 0x1a
            //   85ff                 | test                edi, edi
            //   7514                 | jne                 0x16
            //   217e14               | and                 dword ptr [esi + 0x14], edi

        $sequence_9 = { 66832600 33c0 3bc7 1bc0 f7d8 }
            // n = 5, score = 600
            //   66832600             | and                 word ptr [esi], 0
            //   33c0                 | xor                 eax, eax
            //   3bc7                 | cmp                 eax, edi
            //   1bc0                 | sbb                 eax, eax
            //   f7d8                 | neg                 eax

        $sequence_10 = { 8bf0 83661400 c7461807000000 6683660400 e8???????? }
            // n = 5, score = 600
            //   8bf0                 | mov                 esi, eax
            //   83661400             | and                 dword ptr [esi + 0x14], 0
            //   c7461807000000       | mov                 dword ptr [esi + 0x18], 7
            //   6683660400           | and                 word ptr [esi + 4], 0
            //   e8????????           |                     

        $sequence_11 = { e8???????? 51 56 8d4508 8bf1 50 8975f0 }
            // n = 7, score = 600
            //   e8????????           |                     
            //   51                   | push                ecx
            //   56                   | push                esi
            //   8d4508               | lea                 eax, [ebp + 8]
            //   8bf1                 | mov                 esi, ecx
            //   50                   | push                eax
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi

        $sequence_12 = { cc 833e00 7505 e8???????? }
            // n = 4, score = 600
            //   cc                   | int3                
            //   833e00               | cmp                 dword ptr [esi], 0
            //   7505                 | jne                 7
            //   e8????????           |                     

        $sequence_13 = { 6a01 e8???????? 59 c3 55 8bec 83ec14 }
            // n = 7, score = 600
            //   6a01                 | push                1
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec14               | sub                 esp, 0x14

        $sequence_14 = { 7514 217e14 83f808 7205 }
            // n = 4, score = 600
            //   7514                 | jne                 0x16
            //   217e14               | and                 dword ptr [esi + 0x14], edi
            //   83f808               | cmp                 eax, 8
            //   7205                 | jb                  7

        $sequence_15 = { 8b4e18 83f908 53 8d5604 7207 8b1a 895dfc }
            // n = 7, score = 600
            //   8b4e18               | mov                 ecx, dword ptr [esi + 0x18]
            //   83f908               | cmp                 ecx, 8
            //   53                   | push                ebx
            //   8d5604               | lea                 edx, [esi + 4]
            //   7207                 | jb                  9
            //   8b1a                 | mov                 ebx, dword ptr [edx]
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx

        $sequence_16 = { 895114 50 885104 e8???????? c7442414ffffffff 8b4c240c }
            // n = 6, score = 600
            //   895114               | mov                 dword ptr [ecx + 0x14], edx
            //   50                   | push                eax
            //   885104               | mov                 byte ptr [ecx + 4], dl
            //   e8????????           |                     
            //   c7442414ffffffff     | mov                 dword ptr [esp + 0x14], 0xffffffff
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]

    condition:
        7 of them and filesize < 827392
}