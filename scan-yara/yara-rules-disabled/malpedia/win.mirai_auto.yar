rule win_mirai_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mirai."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mirai"
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
        $sequence_0 = { e8???????? 83c408 85c0 7535 8b742408 50 68???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   7535                 | jne                 0x37
            //   8b742408             | mov                 esi, dword ptr [esp + 8]
            //   50                   | push                eax
            //   68????????           |                     

        $sequence_1 = { 8b8d48feffff e8???????? 8d4db0 e8???????? 8365fc00 83a578feffff00 8d8554feffff }
            // n = 7, score = 100
            //   8b8d48feffff         | mov                 ecx, dword ptr [ebp - 0x1b8]
            //   e8????????           |                     
            //   8d4db0               | lea                 ecx, [ebp - 0x50]
            //   e8????????           |                     
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   83a578feffff00       | and                 dword ptr [ebp - 0x188], 0
            //   8d8554feffff         | lea                 eax, [ebp - 0x1ac]

        $sequence_2 = { e8???????? 83c40c 5d c3 8b5510 8b450c 8b4904 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]

        $sequence_3 = { 8bf3 c1ee18 334cb500 8b2d???????? 0fb6f2 334cb500 8b35???????? }
            // n = 7, score = 100
            //   8bf3                 | mov                 esi, ebx
            //   c1ee18               | shr                 esi, 0x18
            //   334cb500             | xor                 ecx, dword ptr [ebp + esi*4]
            //   8b2d????????         |                     
            //   0fb6f2               | movzx               esi, dl
            //   334cb500             | xor                 ecx, dword ptr [ebp + esi*4]
            //   8b35????????         |                     

        $sequence_4 = { 8bcd e8???????? 8bc8 e8???????? 8b10 8b12 6a5c }
            // n = 7, score = 100
            //   8bcd                 | mov                 ecx, ebp
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b10                 | mov                 edx, dword ptr [eax]
            //   8b12                 | mov                 edx, dword ptr [edx]
            //   6a5c                 | push                0x5c

        $sequence_5 = { e8???????? 8b54244c 56 53 52 53 ff15???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8b54244c             | mov                 edx, dword ptr [esp + 0x4c]
            //   56                   | push                esi
            //   53                   | push                ebx
            //   52                   | push                edx
            //   53                   | push                ebx
            //   ff15????????         |                     

        $sequence_6 = { c3 55 8bec 51 51 6a17 68???????? }
            // n = 7, score = 100
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   51                   | push                ecx
            //   6a17                 | push                0x17
            //   68????????           |                     

        $sequence_7 = { c20400 55 8bec 83ec14 894df0 c745f401000000 837df400 }
            // n = 7, score = 100
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec14               | sub                 esp, 0x14
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx
            //   c745f401000000       | mov                 dword ptr [ebp - 0xc], 1
            //   837df400             | cmp                 dword ptr [ebp - 0xc], 0

        $sequence_8 = { 8bbcbd00100000 81e70000ff00 33f7 0fb6fd 8bbcbd00100000 81e700ff0000 33f7 }
            // n = 7, score = 100
            //   8bbcbd00100000       | mov                 edi, dword ptr [ebp + edi*4 + 0x1000]
            //   81e70000ff00         | and                 edi, 0xff0000
            //   33f7                 | xor                 esi, edi
            //   0fb6fd               | movzx               edi, ch
            //   8bbcbd00100000       | mov                 edi, dword ptr [ebp + edi*4 + 0x1000]
            //   81e700ff0000         | and                 edi, 0xff00
            //   33f7                 | xor                 esi, edi

        $sequence_9 = { e8???????? 8365f800 8b45fc c9 c3 55 8bec }
            // n = 7, score = 100
            //   e8????????           |                     
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   c9                   | leave               
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

    condition:
        7 of them and filesize < 7086080
}