rule win_owlproxy_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.owlproxy."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.owlproxy"
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
        $sequence_0 = { 488d942450010000 488d8c2430010000 e8???????? 90 4c8d842430010000 4883bc244801000008 4c0f43842430010000 }
            // n = 7, score = 200
            //   488d942450010000     | lea                 ecx, [ebx + 4]
            //   488d8c2430010000     | dec                 esp
            //   e8????????           |                     
            //   90                   | lea                 eax, [0xb3bb]
            //   4c8d842430010000     | inc                 ecx
            //   4883bc244801000008     | lea    edx, [edx + 0x16]
            //   4c0f43842430010000     | jne    0x9d

        $sequence_1 = { 488bcb 488905???????? ff15???????? 488d151b580100 483305???????? 488bcb 488905???????? }
            // n = 7, score = 200
            //   488bcb               | mov                 eax, dword ptr [esp + 0x70]
            //   488905????????       |                     
            //   ff15????????         |                     
            //   488d151b580100       | dec                 ecx
            //   483305????????       |                     
            //   488bcb               | sub                 eax, edi
            //   488905????????       |                     

        $sequence_2 = { 4889442428 488d442450 4533c0 488bcf 664489a588010000 4889442420 ff15???????? }
            // n = 7, score = 200
            //   4889442428           | jmp                 0x1e7
            //   488d442450           | dec                 ecx
            //   4533c0               | mov                 ecx, dword ptr [esp]
            //   488bcf               | dec                 eax
            //   664489a588010000     | inc                 ebx
            //   4889442420           | cmp                 word ptr [eax + ebx*2], 0
            //   ff15????????         |                     

        $sequence_3 = { 488d4c2440 e8???????? eb27 49c747180f000000 49c7471000000000 41c60700 4533c0 }
            // n = 7, score = 200
            //   488d4c2440           | dec                 eax
            //   e8????????           |                     
            //   eb27                 | mov                 dword ptr [esp + 0x20], eax
            //   49c747180f000000     | dec                 eax
            //   49c7471000000000     | mov                 ecx, dword ptr [ebp + 0x1d8]
            //   41c60700             | dec                 eax
            //   4533c0               | xor                 ecx, esp

        $sequence_4 = { e8???????? 448bc0 488bd3 488bce e8???????? 84c0 7406 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   448bc0               | lea                 eax, [0x16e8a]
            //   488bd3               | dec                 eax
            //   488bce               | lea                 edx, [0x22563]
            //   e8????????           |                     
            //   84c0                 | dec                 eax
            //   7406                 | lea                 ecx, [esp + 0x20]

        $sequence_5 = { e8???????? 90 488b4527 4c8b4d0f 6690 48837de700 740a }
            // n = 7, score = 200
            //   e8????????           |                     
            //   90                   | jne                 0x1c3
            //   488b4527             | dec                 ecx
            //   4c8b4d0f             | mov                 edx, dword ptr [edi]
            //   6690                 | dec                 eax
            //   48837de700           | lea                 ecx, [0x1b7ea]
            //   740a                 | dec                 eax

        $sequence_6 = { 4c8bc6 498bd7 488d0c28 e8???????? 4c8b4708 488b542478 }
            // n = 6, score = 200
            //   4c8bc6               | dec                 eax
            //   498bd7               | lea                 edx, [esp + 0x28]
            //   488d0c28             | mov                 dword ptr [esp + 0x20], 0x14
            //   e8????????           |                     
            //   4c8b4708             | inc                 ecx
            //   488b542478           | mov                 esi, ebp

        $sequence_7 = { f6c101 7527 458bc6 488d156ee10000 663b1a }
            // n = 5, score = 200
            //   f6c101               | cmp                 dword ptr [edi - 0x10], eax
            //   7527                 | je                  0x9c6
            //   458bc6               | dec                 eax
            //   488d156ee10000       | lea                 edi, [esp + 0x20]
            //   663b1a               | dec                 ecx

        $sequence_8 = { 4889442428 488d054eff0100 4889442440 488b442468 48634804 488d0581fe0100 4889440c68 }
            // n = 7, score = 200
            //   4889442428           | dec                 eax
            //   488d054eff0100       | inc                 ebx
            //   4889442440           | dec                 ecx
            //   488b442468           | lea                 eax, [edi + ebx]
            //   48634804             | dec                 eax
            //   488d0581fe0100       | cmp                 eax, esi
            //   4889440c68           | jne                 0x171

        $sequence_9 = { 89442420 4c8bce 4533c0 488b5610 488b4da8 ff15???????? 85c0 }
            // n = 7, score = 200
            //   89442420             | mov                 edi, dword ptr [esi]
            //   4c8bce               | jmp                 0x39
            //   4533c0               | dec                 esp
            //   488b5610             | lea                 esi, [0x1c7e7]
            //   488b4da8             | mov                 edi, 1
            //   ff15????????         |                     
            //   85c0                 | xor                 ecx, ecx

    condition:
        7 of them and filesize < 475136
}