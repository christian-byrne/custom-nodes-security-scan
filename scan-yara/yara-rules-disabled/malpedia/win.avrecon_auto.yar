rule win_avrecon_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.avrecon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.avrecon"
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
        $sequence_0 = { 56 e8???????? 85c0 0f8577020000 8d8584fbffff 50 56 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8577020000         | jne                 0x27d
            //   8d8584fbffff         | lea                 eax, [ebp - 0x47c]
            //   50                   | push                eax
            //   56                   | push                esi

        $sequence_1 = { 89b5f0fdffff 899decfdffff 89b5f4feffff 899df0feffff ff15???????? 8945fc }
            // n = 6, score = 300
            //   89b5f0fdffff         | mov                 dword ptr [ebp - 0x210], esi
            //   899decfdffff         | mov                 dword ptr [ebp - 0x214], ebx
            //   89b5f4feffff         | mov                 dword ptr [ebp - 0x10c], esi
            //   899df0feffff         | mov                 dword ptr [ebp - 0x110], ebx
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_2 = { 56 47 e8???????? 0fb7f0 663bf3 0f869b030000 }
            // n = 6, score = 300
            //   56                   | push                esi
            //   47                   | inc                 edi
            //   e8????????           |                     
            //   0fb7f0               | movzx               esi, ax
            //   663bf3               | cmp                 si, bx
            //   0f869b030000         | jbe                 0x3a1

        $sequence_3 = { e8???????? 53 ff15???????? 8b35???????? 8d4554 50 0fb705???????? }
            // n = 7, score = 300
            //   e8????????           |                     
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   8b35????????         |                     
            //   8d4554               | lea                 eax, [ebp + 0x54]
            //   50                   | push                eax
            //   0fb705????????       |                     

        $sequence_4 = { e8???????? 83c410 5e c3 55 8bec 81ec04010000 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec04010000         | sub                 esp, 0x104

        $sequence_5 = { 50 6880000000 57 ff7508 ffd6 6a04 8d45f8 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   6880000000           | push                0x80
            //   57                   | push                edi
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd6                 | call                esi
            //   6a04                 | push                4
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_6 = { 49 7524 50 a3???????? ff15???????? e8???????? }
            // n = 6, score = 300
            //   49                   | dec                 ecx
            //   7524                 | jne                 0x26
            //   50                   | push                eax
            //   a3????????           |                     
            //   ff15????????         |                     
            //   e8????????           |                     

        $sequence_7 = { e8???????? 56 6a08 8d45d8 50 ff7508 c645d800 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   56                   | push                esi
            //   6a08                 | push                8
            //   8d45d8               | lea                 eax, [ebp - 0x28]
            //   50                   | push                eax
            //   ff7508               | push                dword ptr [ebp + 8]
            //   c645d800             | mov                 byte ptr [ebp - 0x28], 0

        $sequence_8 = { 56 8bf8 ff15???????? 668bc7 5f 5e }
            // n = 6, score = 300
            //   56                   | push                esi
            //   8bf8                 | mov                 edi, eax
            //   ff15????????         |                     
            //   668bc7               | mov                 ax, di
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 50 8d85c0f7ffff 50 e8???????? 8d85a8f7ffff 50 894534 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   8d85c0f7ffff         | lea                 eax, [ebp - 0x840]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d85a8f7ffff         | lea                 eax, [ebp - 0x858]
            //   50                   | push                eax
            //   894534               | mov                 dword ptr [ebp + 0x34], eax

    condition:
        7 of them and filesize < 360448
}