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

rule Sliver_Implant_32bit
{
  meta:
    description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    hash =  "911f4106350871ddb1396410d36f2d2eadac1166397e28a553b28678543a9357"
    author = "gssincla@google.com"
    reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
    date = "2022-11-18"
    modified = "2022-11-19"

  strings:
    // We look for the specific switch/case statement case values.

    // case "tcppivot":
    /*
      81 ?? 74 63 70 70     cmp     dword ptr [ecx], 70706374h
      .
      .
      .
      81 ?? 04 69 76 6F 74  cmp     dword ptr [ecx+4], 746F7669h
    */
    $s_tcppivot = { 81 ?? 74 63 70 70 [2-20] 81 ?? 04 69 76 6F 74  }

    // case "wg":
    /*
      66 81 ?? 77 67 cmp     word ptr [eax], 6777h      // "gw"
    */
    $s_wg = { 66 81 ?? 77 67 }

    // case "dns":
    /*
      66 81 ?? 64 6E cmp     word ptr [eax], 6E64h    // "nd"
      .
      .
      .
      80 ?? 02 73    cmp     byte ptr [eax+2], 73h ; 's'
    */
    $s_dns = { 66 81 ?? 64 6E [2-20] 80 ?? 02 73 }

    // case "http":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [eax], 70747468h     // "ptth"
     */
    $s_http = { 81 ?? 68 74 74 70 }

    // case "https":
    /*
      81 ?? 68 74 74 70  cmp     dword ptr [ecx], 70747468h     // "ptth"
      .
      .
      .
      80 ?? 04 73        cmp     byte ptr [ecx+4], 73h ; 's'
    */
    $s_https = { 81 ?? 68 74 74 70 [2-20] 80 ?? 04 73 }

    // case "mtls":       NOTE: this one can be missing due to compilate time config
    /*
      81 ?? 6D 74 6C 73  cmp     dword ptr [eax], 736C746Dh     // "sltm"
    */
    $s_mtls = { 81 ?? 6D 74 6C 73 }

    $fp1 = "cloudfoundry" ascii fullword
  condition:
    4 of ($s*) and not 1 of ($fp*)
}