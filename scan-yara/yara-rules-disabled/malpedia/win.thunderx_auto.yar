rule win_thunderx_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.thunderx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thunderx"
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
        $sequence_0 = { 50 e8???????? c9 c3 c705????????58004200 b001 c3 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   c9                   | leave               
            //   c3                   | ret                 
            //   c705????????58004200     |     
            //   b001                 | mov                 al, 1
            //   c3                   | ret                 

        $sequence_1 = { b9???????? e8???????? 0fb60d???????? 84c0 6a01 58 0f45c8 }
            // n = 7, score = 200
            //   b9????????           |                     
            //   e8????????           |                     
            //   0fb60d????????       |                     
            //   84c0                 | test                al, al
            //   6a01                 | push                1
            //   58                   | pop                 eax
            //   0f45c8               | cmovne              ecx, eax

        $sequence_2 = { 51 53 8b5d10 8bd1 56 57 8955fc }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   8b5d10               | mov                 ebx, dword ptr [ebp + 0x10]
            //   8bd1                 | mov                 edx, ecx
            //   56                   | push                esi
            //   57                   | push                edi
            //   8955fc               | mov                 dword ptr [ebp - 4], edx

        $sequence_3 = { 8d8d9cfbffff e8???????? 8d8d84fbffff e8???????? 8d8d6cfbffff e8???????? }
            // n = 6, score = 200
            //   8d8d9cfbffff         | lea                 ecx, [ebp - 0x464]
            //   e8????????           |                     
            //   8d8d84fbffff         | lea                 ecx, [ebp - 0x47c]
            //   e8????????           |                     
            //   8d8d6cfbffff         | lea                 ecx, [ebp - 0x494]
            //   e8????????           |                     

        $sequence_4 = { 6a02 8d44241c 895c2424 50 53 53 }
            // n = 6, score = 200
            //   6a02                 | push                2
            //   8d44241c             | lea                 eax, [esp + 0x1c]
            //   895c2424             | mov                 dword ptr [esp + 0x24], ebx
            //   50                   | push                eax
            //   53                   | push                ebx
            //   53                   | push                ebx

        $sequence_5 = { e8???????? 84c0 7558 83c718 3b7da0 75ea 8d4de0 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   7558                 | jne                 0x5a
            //   83c718               | add                 edi, 0x18
            //   3b7da0               | cmp                 edi, dword ptr [ebp - 0x60]
            //   75ea                 | jne                 0xffffffec
            //   8d4de0               | lea                 ecx, [ebp - 0x20]

        $sequence_6 = { 89459c 8945a0 e8???????? 84c0 0f858d000000 395f10 }
            // n = 6, score = 200
            //   89459c               | mov                 dword ptr [ebp - 0x64], eax
            //   8945a0               | mov                 dword ptr [ebp - 0x60], eax
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   0f858d000000         | jne                 0x93
            //   395f10               | cmp                 dword ptr [edi + 0x10], ebx

        $sequence_7 = { 03d1 8b0c85701b4200 8a0433 43 88440a2e 8b4dd8 8b55b4 }
            // n = 7, score = 200
            //   03d1                 | add                 edx, ecx
            //   8b0c85701b4200       | mov                 ecx, dword ptr [eax*4 + 0x421b70]
            //   8a0433               | mov                 al, byte ptr [ebx + esi]
            //   43                   | inc                 ebx
            //   88440a2e             | mov                 byte ptr [edx + ecx + 0x2e], al
            //   8b4dd8               | mov                 ecx, dword ptr [ebp - 0x28]
            //   8b55b4               | mov                 edx, dword ptr [ebp - 0x4c]

        $sequence_8 = { 8932 897204 897208 5e 5d c20400 6a18 }
            // n = 7, score = 200
            //   8932                 | mov                 dword ptr [edx], esi
            //   897204               | mov                 dword ptr [edx + 4], esi
            //   897208               | mov                 dword ptr [edx + 8], esi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   c20400               | ret                 4
            //   6a18                 | push                0x18

        $sequence_9 = { 8d8dd0fdffff e8???????? 8d4dac c645fc06 }
            // n = 4, score = 200
            //   8d8dd0fdffff         | lea                 ecx, [ebp - 0x230]
            //   e8????????           |                     
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6

    condition:
        7 of them and filesize < 319488
}