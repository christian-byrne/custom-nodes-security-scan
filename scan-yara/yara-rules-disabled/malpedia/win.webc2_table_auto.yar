rule win_webc2_table_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.webc2_table."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_table"
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
        $sequence_0 = { 8d85e4feffff 50 ff75fc ff15???????? 85c0 0f8461010000 }
            // n = 6, score = 100
            //   8d85e4feffff         | lea                 eax, [ebp - 0x11c]
            //   50                   | push                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f8461010000         | je                  0x167

        $sequence_1 = { 83c410 881d???????? 8345fc04 ff4dec 0f8567feffff }
            // n = 5, score = 100
            //   83c410               | add                 esp, 0x10
            //   881d????????         |                     
            //   8345fc04             | add                 dword ptr [ebp - 4], 4
            //   ff4dec               | dec                 dword ptr [ebp - 0x14]
            //   0f8567feffff         | jne                 0xfffffe6d

        $sequence_2 = { 8dbda1fcffff 889da0fcffff f3ab 66ab aa 8d859cfbffff 6804010000 }
            // n = 7, score = 100
            //   8dbda1fcffff         | lea                 edi, [ebp - 0x35f]
            //   889da0fcffff         | mov                 byte ptr [ebp - 0x360], bl
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   8d859cfbffff         | lea                 eax, [ebp - 0x464]
            //   6804010000           | push                0x104

        $sequence_3 = { 53 894dec ffd6 59 }
            // n = 4, score = 100
            //   53                   | push                ebx
            //   894dec               | mov                 dword ptr [ebp - 0x14], ecx
            //   ffd6                 | call                esi
            //   59                   | pop                 ecx

        $sequence_4 = { 8b45f4 bf???????? 57 50 885c30f4 8b35???????? }
            // n = 6, score = 100
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   bf????????           |                     
            //   57                   | push                edi
            //   50                   | push                eax
            //   885c30f4             | mov                 byte ptr [eax + esi - 0xc], bl
            //   8b35????????         |                     

        $sequence_5 = { 50 53 ff15???????? 85c0 750a ff15???????? 32c0 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750a                 | jne                 0xc
            //   ff15????????         |                     
            //   32c0                 | xor                 al, al

        $sequence_6 = { ff75fc 8d85bcfdffff 50 e8???????? 59 }
            // n = 5, score = 100
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   8d85bcfdffff         | lea                 eax, [ebp - 0x244]
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_7 = { 50 8945e8 e8???????? 83c40c 895df8 8d45c4 }
            // n = 6, score = 100
            //   50                   | push                eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   8d45c4               | lea                 eax, [ebp - 0x3c]

        $sequence_8 = { e8???????? 0fb745e0 50 0fb745de 50 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   0fb745e0             | movzx               eax, word ptr [ebp - 0x20]
            //   50                   | push                eax
            //   0fb745de             | movzx               eax, word ptr [ebp - 0x22]
            //   50                   | push                eax

        $sequence_9 = { ff7508 6a01 50 ff15???????? 56 }
            // n = 5, score = 100
            //   ff7508               | push                dword ptr [ebp + 8]
            //   6a01                 | push                1
            //   50                   | push                eax
            //   ff15????????         |                     
            //   56                   | push                esi

    condition:
        7 of them and filesize < 49152
}