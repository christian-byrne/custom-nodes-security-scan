rule win_zumanek_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.zumanek."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zumanek"
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
        $sequence_0 = { fc 81fe382e9330 97 e412 3dd16312c9 103f 0800 }
            // n = 7, score = 100
            //   fc                   | cld                 
            //   81fe382e9330         | cmp                 esi, 0x30932e38
            //   97                   | xchg                eax, edi
            //   e412                 | in                  al, 0x12
            //   3dd16312c9           | cmp                 eax, 0xc91263d1
            //   103f                 | adc                 byte ptr [edi], bh
            //   0800                 | or                  byte ptr [eax], al

        $sequence_1 = { 8802 98 811212242434 48 3c91 4a }
            // n = 6, score = 100
            //   8802                 | mov                 byte ptr [edx], al
            //   98                   | cwde                
            //   811212242434         | adc                 dword ptr [edx], 0x34242412
            //   48                   | dec                 eax
            //   3c91                 | cmp                 al, 0x91
            //   4a                   | dec                 edx

        $sequence_2 = { 894612 4d 2454 48 5b 91 }
            // n = 6, score = 100
            //   894612               | mov                 dword ptr [esi + 0x12], eax
            //   4d                   | dec                 ebp
            //   2454                 | and                 al, 0x54
            //   48                   | dec                 eax
            //   5b                   | pop                 ebx
            //   91                   | xchg                eax, ecx

        $sequence_3 = { 71ef 1a6f35 e30b 5d fc 77f2 f1 }
            // n = 7, score = 100
            //   71ef                 | jno                 0xfffffff1
            //   1a6f35               | sbb                 ch, byte ptr [edi + 0x35]
            //   e30b                 | jecxz               0xd
            //   5d                   | pop                 ebp
            //   fc                   | cld                 
            //   77f2                 | ja                  0xfffffff4
            //   f1                   | int1                

        $sequence_4 = { 1dba45e22f 91 7c8b e459 0920 122424 }
            // n = 6, score = 100
            //   1dba45e22f           | sbb                 eax, 0x2fe245ba
            //   91                   | xchg                eax, ecx
            //   7c8b                 | jl                  0xffffff8d
            //   e459                 | in                  al, 0x59
            //   0920                 | or                  dword ptr [eax], esp
            //   122424               | adc                 ah, byte ptr [esp]

        $sequence_5 = { 386b95 4c 53 196a17 }
            // n = 4, score = 100
            //   386b95               | cmp                 byte ptr [ebx - 0x6b], ch
            //   4c                   | dec                 esp
            //   53                   | push                ebx
            //   196a17               | sbb                 dword ptr [edx + 0x17], ebp

        $sequence_6 = { 4a e8???????? 86b71986f742 06 58 4c 8812 }
            // n = 7, score = 100
            //   4a                   | dec                 edx
            //   e8????????           |                     
            //   86b71986f742         | xchg                byte ptr [edi + 0x42f78619], dh
            //   06                   | push                es
            //   58                   | pop                 eax
            //   4c                   | dec                 esp
            //   8812                 | mov                 byte ptr [edx], dl

        $sequence_7 = { c101f6 53 32b879629b65 76a2 43 fc }
            // n = 6, score = 100
            //   c101f6               | rol                 dword ptr [ecx], 0xf6
            //   53                   | push                ebx
            //   32b879629b65         | xor                 bh, byte ptr [eax + 0x659b6279]
            //   76a2                 | jbe                 0xffffffa4
            //   43                   | inc                 ebx
            //   fc                   | cld                 

        $sequence_8 = { d9c3 ab 5f c50f 9d 54 f233591b }
            // n = 7, score = 100
            //   d9c3                 | fld                 st(3)
            //   ab                   | stosd               dword ptr es:[edi], eax
            //   5f                   | pop                 edi
            //   c50f                 | lds                 ecx, ptr [edi]
            //   9d                   | popfd               
            //   54                   | push                esp
            //   f233591b             | xor                 ebx, dword ptr [ecx + 0x1b]

        $sequence_9 = { 5a c59cd53a93a658 98 9f f5 6b80e7fa856bb2 55 }
            // n = 7, score = 100
            //   5a                   | pop                 edx
            //   c59cd53a93a658       | lds                 ebx, ptr [ebp + edx*8 + 0x58a6933a]
            //   98                   | cwde                
            //   9f                   | lahf                
            //   f5                   | cmc                 
            //   6b80e7fa856bb2       | imul                eax, dword ptr [eax + 0x6b85fae7], -0x4e
            //   55                   | push                ebp

    condition:
        7 of them and filesize < 58867712
}