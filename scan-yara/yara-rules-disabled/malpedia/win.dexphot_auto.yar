rule win_dexphot_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2020-10-14"
        version = "1"
        description = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dexphot"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
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
        $sequence_0 = { 8b45f0 8b4010 0345f8 8945e4 33c0 }
            // n = 5, score = 400
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   8b4010               | mov                 eax, dword ptr [eax + 0x10]
            //   0345f8               | add                 eax, dword ptr [ebp - 8]
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   33c0                 | xor                 eax, eax

        $sequence_1 = { 8b45fc 8d5018 8b45fc e8???????? 0345fc }
            // n = 5, score = 400
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8d5018               | lea                 edx, [eax + 0x18]
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   e8????????           |                     
            //   0345fc               | add                 eax, dword ptr [ebp - 4]

        $sequence_2 = { b900010000 e8???????? 8b45a8 8d55ac e8???????? }
            // n = 5, score = 400
            //   b900010000           | mov                 ecx, 0x100
            //   e8????????           |                     
            //   8b45a8               | mov                 eax, dword ptr [ebp - 0x58]
            //   8d55ac               | lea                 edx, [ebp - 0x54]
            //   e8????????           |                     

        $sequence_3 = { 99 890424 89542404 eb61 6a05 }
            // n = 5, score = 400
            //   99                   | cdq                 
            //   890424               | mov                 dword ptr [esp], eax
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   eb61                 | jmp                 0x63
            //   6a05                 | push                5

        $sequence_4 = { e8???????? e9???????? 8bc3 e8???????? e9???????? 8b4308 }
            // n = 6, score = 400
            //   e8????????           |                     
            //   e9????????           |                     
            //   8bc3                 | mov                 eax, ebx
            //   e8????????           |                     
            //   e9????????           |                     
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]

        $sequence_5 = { 8b4510 50 ff750c ff7508 ff15???????? }
            // n = 5, score = 400
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ff15????????         |                     

        $sequence_6 = { 99 890424 89542404 eb61 6a05 6a00 6800040000 }
            // n = 7, score = 400
            //   99                   | cdq                 
            //   890424               | mov                 dword ptr [esp], eax
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   eb61                 | jmp                 0x63
            //   6a05                 | push                5
            //   6a00                 | push                0
            //   6800040000           | push                0x400

        $sequence_7 = { 8b45e8 0145d4 33c0 55 68???????? }
            // n = 5, score = 400
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   0145d4               | add                 dword ptr [ebp - 0x2c], eax
            //   33c0                 | xor                 eax, eax
            //   55                   | push                ebp
            //   68????????           |                     

        $sequence_8 = { 8d460c e8???????? 6a00 e8???????? 8bc6 }
            // n = 5, score = 400
            //   8d460c               | lea                 eax, [esi + 0xc]
            //   e8????????           |                     
            //   6a00                 | push                0
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_9 = { 8d45e8 50 e8???????? 668b13 66b90700 }
            // n = 5, score = 400
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   e8????????           |                     
            //   668b13               | mov                 dx, word ptr [ebx]
            //   66b90700             | mov                 cx, 7

    condition:
        7 of them and filesize < 25404416
}