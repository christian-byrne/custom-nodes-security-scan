rule win_sidewalk_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sidewalk."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sidewalk"
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
        $sequence_0 = { 4403e8 4133db 418bcd c1c307 }
            // n = 4, score = 200
            //   4403e8               | dec                 eax
            //   4133db               | mov                 ecx, edi
            //   418bcd               | dec                 eax
            //   c1c307               | test                eax, eax

        $sequence_1 = { 0bc8 41890c10 488d5204 4983e901 75d4 }
            // n = 5, score = 200
            //   0bc8                 | test                eax, eax
            //   41890c10             | cmp                 dword ptr [eax + 0xc], 0
            //   488d5204             | je                  7
            //   4983e901             | dec                 eax
            //   75d4                 | test                ecx, ecx

        $sequence_2 = { 33c3 c1c207 c1c00c 4403c8 4533d1 }
            // n = 5, score = 200
            //   33c3                 | jl                  0xffffffe7
            //   c1c207               | dec                 eax
            //   c1c00c               | add                 esi, 0x40
            //   4403c8               | dec                 eax
            //   4533d1               | add                 ebx, 0x40

        $sequence_3 = { 488b05???????? 83780c00 7405 e8???????? }
            // n = 4, score = 200
            //   488b05????????       |                     
            //   83780c00             | cmp                 dword ptr [eax + 0xc], 0
            //   7405                 | je                  7
            //   e8????????           |                     

        $sequence_4 = { 488d040a 483bc6 7ce2 4883c640 }
            // n = 4, score = 200
            //   488d040a             | mov                 byte ptr [eax + ecx], al
            //   483bc6               | dec                 eax
            //   7ce2                 | inc                 ecx
            //   4883c640             | or                  ecx, eax

        $sequence_5 = { 8bc2 33c6 c1c010 4403d8 4133db }
            // n = 5, score = 200
            //   8bc2                 | dec                 eax
            //   33c6                 | test                eax, eax
            //   c1c010               | dec                 eax
            //   4403d8               | test                eax, eax
            //   4133db               | jne                 0x10

        $sequence_6 = { 750e 488bcf ff15???????? 4885c0 }
            // n = 4, score = 200
            //   750e                 | test                eax, eax
            //   488bcf               | dec                 eax
            //   ff15????????         |                     
            //   4885c0               | test                eax, eax

        $sequence_7 = { c1c610 4433f2 c1c710 4403df 41c1c610 4503e6 }
            // n = 6, score = 200
            //   c1c610               | test                eax, eax
            //   4433f2               | jne                 0x13
            //   c1c710               | dec                 eax
            //   4403df               | mov                 ecx, edi
            //   41c1c610             | cmp                 dword ptr [eax + 0xc], 0
            //   4503e6               | je                  0xb

        $sequence_8 = { 41c1c610 4503e6 4403cb 4533d1 4403ee 41c1c210 418bc3 }
            // n = 7, score = 200
            //   41c1c610             | or                  ecx, eax
            //   4503e6               | inc                 ecx
            //   4403cb               | mov                 dword ptr [eax + edx], ecx
            //   4533d1               | dec                 eax
            //   4403ee               | lea                 edx, [edx + 4]
            //   41c1c210             | dec                 ecx
            //   418bc3               | sub                 ecx, 1

        $sequence_9 = { 884202 884a03 4183f810 7ccc }
            // n = 4, score = 200
            //   884202               | test                eax, eax
            //   884a03               | mov                 al, byte ptr [edi + ecx]
            //   4183f810             | xor                 al, byte ptr [ecx]
            //   7ccc                 | inc                 ecx

        $sequence_10 = { 0fb642fe c1e108 0bc8 41890c10 }
            // n = 4, score = 200
            //   0fb642fe             | jne                 0xffffffda
            //   c1e108               | dec                 eax
            //   0bc8                 | arpl                word ptr [ebp + 0x7f], ax
            //   41890c10             | mov                 byte ptr [edx + 2], al

        $sequence_11 = { ff15???????? 4885c0 750e 488bcf }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   4885c0               | dec                 eax
            //   750e                 | test                eax, eax
            //   488bcf               | jne                 0x10

        $sequence_12 = { 8a040f 3201 41880408 48ffc1 }
            // n = 4, score = 200
            //   8a040f               | jne                 0x10
            //   3201                 | dec                 eax
            //   41880408             | mov                 ecx, edi
            //   48ffc1               | dec                 eax

    condition:
        7 of them and filesize < 237568
}