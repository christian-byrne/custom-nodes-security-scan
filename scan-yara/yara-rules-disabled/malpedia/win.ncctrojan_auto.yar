rule win_ncctrojan_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.ncctrojan."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ncctrojan"
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
        $sequence_0 = { 7536 8b85e8feffff 85c0 750a 68???????? }
            // n = 5, score = 500
            //   7536                 | jne                 0x38
            //   8b85e8feffff         | mov                 eax, dword ptr [ebp - 0x118]
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   68????????           |                     

        $sequence_1 = { 68???????? e9???????? 83f801 750a }
            // n = 4, score = 500
            //   68????????           |                     
            //   e9????????           |                     
            //   83f801               | cmp                 eax, 1
            //   750a                 | jne                 0xc

        $sequence_2 = { 83f801 750a 68???????? e9???????? 83f802 }
            // n = 5, score = 500
            //   83f801               | cmp                 eax, 1
            //   750a                 | jne                 0xc
            //   68????????           |                     
            //   e9????????           |                     
            //   83f802               | cmp                 eax, 2

        $sequence_3 = { 68e9fd0000 ffd6 8d8decfdffff 5f 8d5102 5e 668b01 }
            // n = 7, score = 400
            //   68e9fd0000           | push                0xfde9
            //   ffd6                 | call                esi
            //   8d8decfdffff         | lea                 ecx, [ebp - 0x214]
            //   5f                   | pop                 edi
            //   8d5102               | lea                 edx, [ecx + 2]
            //   5e                   | pop                 esi
            //   668b01               | mov                 ax, word ptr [ecx]

        $sequence_4 = { 8b442420 83c40c 83c008 836c240c01 89442414 0f85fffdffff }
            // n = 6, score = 400
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   83c40c               | add                 esp, 0xc
            //   83c008               | add                 eax, 8
            //   836c240c01           | sub                 dword ptr [esp + 0xc], 1
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   0f85fffdffff         | jne                 0xfffffe05

        $sequence_5 = { 8d4a10 0f1f840000000000 0f1041f0 83c020 }
            // n = 4, score = 400
            //   8d4a10               | lea                 ecx, [edx + 0x10]
            //   0f1f840000000000     | nop                 dword ptr [eax + eax]
            //   0f1041f0             | movups              xmm0, xmmword ptr [ecx - 0x10]
            //   83c020               | add                 eax, 0x20

        $sequence_6 = { ffd6 50 8d85dcfdffff 50 }
            // n = 4, score = 400
            //   ffd6                 | call                esi
            //   50                   | push                eax
            //   8d85dcfdffff         | lea                 eax, [ebp - 0x224]
            //   50                   | push                eax

        $sequence_7 = { e8???????? 83c40c 85c0 752f 6a06 8d85c4bfffff }
            // n = 6, score = 400
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   85c0                 | test                eax, eax
            //   752f                 | jne                 0x31
            //   6a06                 | push                6
            //   8d85c4bfffff         | lea                 eax, [ebp - 0x403c]

        $sequence_8 = { 51 f2c3 8b4df0 33cd f2e8bef6ffff }
            // n = 5, score = 300
            //   51                   | push                ecx
            //   f2c3                 | bnd ret             
            //   8b4df0               | mov                 ecx, dword ptr [ebp - 0x10]
            //   33cd                 | xor                 ecx, ebp
            //   f2e8bef6ffff         | bnd call            0xfffff6c4

        $sequence_9 = { 83c414 e8???????? 84c0 7517 }
            // n = 4, score = 300
            //   83c414               | add                 esp, 0x14
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7517                 | jne                 0x19

        $sequence_10 = { 33c5 8945fc 56 6890010000 }
            // n = 4, score = 300
            //   33c5                 | xor                 eax, ebp
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   56                   | push                esi
            //   6890010000           | push                0x190

        $sequence_11 = { 83faff 0f94c0 84c0 7405 }
            // n = 4, score = 300
            //   83faff               | cmp                 edx, -1
            //   0f94c0               | sete                al
            //   84c0                 | test                al, al
            //   7405                 | je                  7

        $sequence_12 = { 83c418 83c008 03c6 8bcf }
            // n = 4, score = 300
            //   83c418               | add                 esp, 0x18
            //   83c008               | add                 eax, 8
            //   03c6                 | add                 eax, esi
            //   8bcf                 | mov                 ecx, edi

        $sequence_13 = { 0fb601 50 8d45d0 68???????? 50 }
            // n = 5, score = 300
            //   0fb601               | movzx               eax, byte ptr [ecx]
            //   50                   | push                eax
            //   8d45d0               | lea                 eax, [ebp - 0x30]
            //   68????????           |                     
            //   50                   | push                eax

        $sequence_14 = { 83ec14 c645fc1f 8d95e8feffff 8bcc }
            // n = 4, score = 300
            //   83ec14               | sub                 esp, 0x14
            //   c645fc1f             | mov                 byte ptr [ebp - 4], 0x1f
            //   8d95e8feffff         | lea                 edx, [ebp - 0x118]
            //   8bcc                 | mov                 ecx, esp

        $sequence_15 = { 668bc1 8be5 5d c3 56 8bf1 }
            // n = 6, score = 300
            //   668bc1               | mov                 ax, cx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx

    condition:
        7 of them and filesize < 1160192
}