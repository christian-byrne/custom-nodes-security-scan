rule win_doublefinger_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.doublefinger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doublefinger"
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
        $sequence_0 = { 4533c0 8b942458010000 488b4c2450 e8???????? 48898424c8020000 4533c0 8b94245c010000 }
            // n = 7, score = 100
            //   4533c0               | dec                 eax
            //   8b942458010000       | mov                 ecx, dword ptr [esp + 0x48]
            //   488b4c2450           | nop                 
            //   e8????????           |                     
            //   48898424c8020000     | mov                 ecx, eax
            //   4533c0               | dec                 esp
            //   8b94245c010000       | lea                 ecx, [esp + 0x60]

        $sequence_1 = { 89442428 8b442424 ffc8 89442424 }
            // n = 4, score = 100
            //   89442428             | dec                 eax
            //   8b442424             | mov                 edx, dword ptr [esp + 0x198]
            //   ffc8                 | dec                 eax
            //   89442424             | mov                 ecx, dword ptr [esp + 0x1c8]

        $sequence_2 = { eb4b 4c8d057b820000 baeb030000 ff15???????? eb37 488d542420 ff15???????? }
            // n = 7, score = 100
            //   eb4b                 | mov                 dword ptr [esp + 0x280], eax
            //   4c8d057b820000       | inc                 ebp
            //   baeb030000           | xor                 eax, eax
            //   ff15????????         |                     
            //   eb37                 | mov                 edx, dword ptr [esp + 0x164]
            //   488d542420           | inc                 ebp
            //   ff15????????         |                     

        $sequence_3 = { 0000 006689 442432 b845000000 6689442434 b84d000000 6689442436 }
            // n = 7, score = 100
            //   0000                 | mov                 edx, dword ptr [esp + 0x198]
            //   006689               | dec                 eax
            //   442432               | mov                 ecx, dword ptr [esp + 0x1c8]
            //   b845000000           | dec                 eax
            //   6689442434           | mov                 dword ptr [esp + 0x298], eax
            //   b84d000000           | inc                 ebp
            //   6689442436           | xor                 eax, eax

        $sequence_4 = { 894c2408 4883ec18 488d442420 4889442408 }
            // n = 4, score = 100
            //   894c2408             | mov                 eax, ecx
            //   4883ec18             | dec                 eax
            //   488d442420           | mov                 dword ptr [esp + 0x1e0], eax
            //   4889442408           | dec                 eax

        $sequence_5 = { 48898424c8010000 c744245c00000000 486344245c 488b8c24d0000000 }
            // n = 4, score = 100
            //   48898424c8010000     | add                 eax, 4
            //   c744245c00000000     | mov                 dword ptr [esp + 4], eax
            //   486344245c           | mov                 eax, dword ptr [esp]
            //   488b8c24d0000000     | cmp                 dword ptr [esp + 4], eax

        $sequence_6 = { 4889442450 4533c0 8b9424c0010000 488b4c2450 e8???????? 48898424e8020000 }
            // n = 6, score = 100
            //   4889442450           | jae                 0x1346
            //   4533c0               | dec                 eax
            //   8b9424c0010000       | arpl                word ptr [esp + 0x20], ax
            //   488b4c2450           | mov                 dword ptr [esp + 0x20], eax
            //   e8????????           |                     
            //   48898424e8020000     | mov                 eax, dword ptr [esp + 0x24]

        $sequence_7 = { 33d2 488d41ff 4883f8fd 773c b84d5a0000 663901 }
            // n = 6, score = 100
            //   33d2                 | dec                 esp
            //   488d41ff             | mov                 ecx, edi
            //   4883f8fd             | dec                 ebp
            //   773c                 | mov                 eax, esi
            //   b84d5a0000           | dec                 eax
            //   663901               | mov                 edx, esi

        $sequence_8 = { 488b00 ba01000000 488b4c2438 ff90b8000000 }
            // n = 4, score = 100
            //   488b00               | dec                 eax
            //   ba01000000           | mov                 dword ptr [esp + 8], eax
            //   488b4c2438           | dec                 eax
            //   ff90b8000000         | mov                 eax, dword ptr [esp + 8]

        $sequence_9 = { ff9424c0000000 4889842480010000 b875000000 6689842400010000 b872000000 6689842402010000 }
            // n = 6, score = 100
            //   ff9424c0000000       | mov                 edx, dword ptr [esp + 0x2d8]
            //   4889842480010000     | dec                 eax
            //   b875000000           | mov                 ecx, dword ptr [esp + 0x180]
            //   6689842400010000     | call                dword ptr [esp + 0xb8]
            //   b872000000           | dec                 eax
            //   6689842402010000     | mov                 dword ptr [esp + 0x308], eax

    condition:
        7 of them and filesize < 115712
}