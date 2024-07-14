/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule Sliver_Implant_64bit
{
  meta:
    description = "Sliver 64-bit implant (with and without --debug flag at compile)"
    hash =  "2d1c9de42942a16c88a042f307f0ace215cdc67241432e1152080870fe95ea87"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      48 ?? 74 63 70 70 69 76 6F 74 mov     rcx, 746F766970706374h
    */
    $s_tcppivot = { 48 ?? 74 63 70 70 69 76 6F 74 }


    // case "namedpipe":
    /*
      48 ?? 6E 61 6D 65 64 70 69 70 mov     rsi, 70697064656D616Eh      // "pipdeman"
      .
      .
      .
      80 ?? 08 65 cmp     byte ptr [rdx+8], 65h ; 'e'

    */
    $s_namedpipe = { 48 ?? 6E 61 6D 65 64 70 69 70 [2-32] 80 ?? 08 65 }

    // case "https":
    /*
      81 3A 68 74 74 70 cmp     dword ptr [rdx], 70747468h          // "ptth"
      .
      .
      .
      80 7A 04 73       cmp     byte ptr [rdx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-32] 80 ?? 04 73 }

    // case "wg":
    /*
      66 81 3A 77 67 cmp     word ptr [rdx], 6777h      // "gw"
    */
    $s_wg = {66 81 ?? 77 67}


    // case "dns":
    /*
      66 81 3A 64 6E cmp     word ptr [rdx], 6E64h     // "nd"
      .
      .
      .
      80 7A 02 73    cmp     byte ptr [rdx+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "mtls":         // This one may or may not be in the file, depending on the config flags.
    /*
       81 ?? 6D 74 6C 73 cmp   dword ptr [rdx], 736C746Dh          // "mtls"
    */
    $s_mtls = {  81 ?? 6D 74 6C 73  }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    5 of ($s*) and not 1 of ($fp*)
}
