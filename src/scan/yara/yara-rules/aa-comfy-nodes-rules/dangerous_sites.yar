
rule SUSP_Websites_In_Compressed_Data {
  meta:
    author = "christian-byrne"
    description = "Detects references to suspicious sites inside compressed or encoded data"
    organization = ""
    version = "1.3"
    date = "17.07.2024"
    category = "C2"
    tags = "ComfyUI"
    severity = "high"
    license = "Unlicense"
    
  strings:
    $site_0 = "https://hastebin.com" nocase
    $site_0_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 11 49 D4 81 14 00 00 00}
    $site_0_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 DC 33 E1 1A 00 00 04 99 80 00 01 80 10 3A 63 CC 00 20 00 22 87 A8 D1 93 C5 0A 60 00 28 05 33 0F 66 92 50 D9 07 E2 EE 48 A7 0A 12 1B 86 7C 23 40}
    $site_0_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 68 61 73 74 65 62 69 6E 2E 63 6F 6D 00 4B 81 2B 32 31 F7 9A 17 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_0_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 CF 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 4F 2E 07 87}
    $site_0_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 CF 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 4F 2E 07 87}
    $site_0_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 68 61 73 74 65 62 69 6E 2E 63 6F 6D 00 00 00 00}
    $site_0_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 68 61 73 74 65 62 69 6E 2E 63 6F 6D}
    $site_0_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 68 61 73 74 65 62 69 6E 2E 63 6F 6D}
    $site_0_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 FF 35 DA BE 26 02 03 0B 94 00 04 94 00 B4 83 02 11 49 D4 81 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 21 10 68 02 68 74 74 70 73 3A 2F 2F 68 61 73 74 65 62 69 6E 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_0_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 11 49 D4 81 14 00 00 00}
    $site_0_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 DC 33 E1 1A 00 00 04 99 80 00 01 80 10 3A 63 CC 00 20 00 22 87 A8 D1 93 C5 0A 60 00 28 05 33 0F 66 92 50 D9 07 E2 EE 48 A7 0A 12 1B 86 7C 23 40}
    $site_0_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 68 61 73 74 65 62 69 6E 2E 63 6F 6D 00 4B 81 2B 32 31 F7 9A 17 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_0_encoded_base64 = "aHR0cHM6Ly9oYXN0ZWJpbi5jb20=" nocase
    $site_0_encoded_hex = "68747470733a2f2f686173746562696e2e636f6d" nocase
    $site_0_encoded_rot13 = "uggcf://unfgrova.pbz"
    $site_0_encoded_base32 = "NB2HI4DTHIXS62DBON2GKYTJNYXGG33N" nocase
    $site_0_encoded_base16 = "68747470733A2F2F686173746562696E2E636F6D" nocase
    $site_0_encoded_base85 = "XmoUNb2=|CXkl}7WnyV=E@N+P"
    $site_0_encoded_ascii85 = "BQS?8F#ks-BOPt(AR]@k/n8g:"
    $site_0_encoded_uu = "aHR0cHM6Ly9oYXN0ZWJpbi5jb20=" nocase
    $site_0_encoded_rot47 = "9EEADi^^92DE63:?]4@>"
    $site_0_encoded_substitution = "kwwsv://kdvwhelq.frp"
    $site_0_encoded_caesar = "kwwsv=22kdvwhelq1frp"

    $site_1 = "https://gofile.io" nocase
    $site_1_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CF 4F CB CC 49 D5 CB CC 07 00 DD D4 9F 9E 11 00 00 00}
    $site_1_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 48 76 5F D4 00 00 03 99 80 00 01 80 10 03 E4 CC 00 20 00 22 9E A7 A2 60 D0 80 68 00 93 95 64 44 5D 04 82 D1 77 24 53 85 09 04 87 65 FD 40}
    $site_1_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 10 68 74 74 70 73 3A 2F 2F 67 6F 66 69 6C 65 2E 69 6F 00 00 00 00 6D 55 6F C9 A3 38 85 43 00 01 29 11 32 0A 70 0E 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_1_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CF 4F CB CC 49 D5 CB CC 07 00 39 61 06 48}
    $site_1_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CF 4F CB CC 49 D5 CB CC 07 00 39 61 06 48}
    $site_1_encoded_lz4 = {04 22 4D 18 68 40 11 00 00 00 00 00 00 00 E8 11 00 00 80 68 74 74 70 73 3A 2F 2F 67 6F 66 69 6C 65 2E 69 6F 00 00 00 00}
    $site_1_encoded_zstd = {28 B5 2F FD 20 11 89 00 00 68 74 74 70 73 3A 2F 2F 67 6F 66 69 6C 65 2E 69 6F}
    $site_1_encoded_snappy = {11 40 68 74 74 70 73 3A 2F 2F 67 6F 66 69 6C 65 2E 69 6F}
    $site_1_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 FA DE 89 C9 26 02 03 0B 91 00 04 91 00 B4 83 02 DD D4 9F 9E 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 EF 23 E2 02 68 74 74 70 73 3A 2F 2F 67 6F 66 69 6C 65 2E 69 6F 1D 77 56 51 03 05 04 00}
    $site_1_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CF 4F CB CC 49 D5 CB CC 07 00 DD D4 9F 9E 11 00 00 00}
    $site_1_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 48 76 5F D4 00 00 03 99 80 00 01 80 10 03 E4 CC 00 20 00 22 9E A7 A2 60 D0 80 68 00 93 95 64 44 5D 04 82 D1 77 24 53 85 09 04 87 65 FD 40}
    $site_1_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 10 68 74 74 70 73 3A 2F 2F 67 6F 66 69 6C 65 2E 69 6F 00 00 00 00 6D 55 6F C9 A3 38 85 43 00 01 29 11 32 0A 70 0E 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_1_encoded_base64 = "aHR0cHM6Ly9nb2ZpbGUuaW8=" nocase
    $site_1_encoded_hex = "68747470733a2f2f676f66696c652e696f" nocase
    $site_1_encoded_rot13 = "uggcf://tbsvyr.vb"
    $site_1_encoded_base32 = "NB2HI4DTHIXS6Z3PMZUWYZJONFXQ====" nocase
    $site_1_encoded_base16 = "68747470733A2F2F676F66696C652E696F" nocase
    $site_1_encoded_base85 = "XmoUNb2=|CXK!X{Y-KKKZv"
    $site_1_encoded_ascii85 = "BQS?8F#ks-B5_BrCh555DZ"
    $site_1_encoded_uu = "aHR0cHM6Ly9nb2ZpbGUuaW8=" nocase
    $site_1_encoded_rot47 = "9EEADi^^8@7:=6]:@"
    $site_1_encoded_substitution = "kwwsv://jriloh.lr"
    $site_1_encoded_caesar = "kwwsv=22jriloh1lr"

    $site_2 = "https://file.io" nocase
    $site_2_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB CC 49 D5 CB CC 07 00 4D 47 E9 5E 0F 00 00 00}
    $site_2_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 11 A4 2B 4D 00 00 03 19 80 00 01 80 10 03 64 CC 00 20 00 22 06 80 68 40 D0 34 00 1D 8F B7 7A 84 B1 F1 77 24 53 85 09 01 1A 42 B4 D0}
    $site_2_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 66 69 6C 65 2E 69 6F 00 00 BA 85 AB 49 49 86 C6 FE 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_2_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB CC 49 D5 CB CC 07 00 2C B2 05 72}
    $site_2_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB CC 49 D5 CB CC 07 00 2C B2 05 72}
    $site_2_encoded_lz4 = {04 22 4D 18 68 40 0F 00 00 00 00 00 00 00 16 0F 00 00 80 68 74 74 70 73 3A 2F 2F 66 69 6C 65 2E 69 6F 00 00 00 00}
    $site_2_encoded_zstd = {28 B5 2F FD 20 0F 79 00 00 68 74 74 70 73 3A 2F 2F 66 69 6C 65 2E 69 6F}
    $site_2_encoded_snappy = {0F 38 68 74 74 70 73 3A 2F 2F 66 69 6C 65 2E 69 6F}
    $site_2_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 52 5F 76 44 26 02 03 0B 8F 00 04 8F 00 B4 83 02 4D 47 E9 5E 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 BA 37 5C 03 68 74 74 70 73 3A 2F 2F 66 69 6C 65 2E 69 6F 1D 77 56 51 03 05 04 00}
    $site_2_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB CC 49 D5 CB CC 07 00 4D 47 E9 5E 0F 00 00 00}
    $site_2_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 11 A4 2B 4D 00 00 03 19 80 00 01 80 10 03 64 CC 00 20 00 22 06 80 68 40 D0 34 00 1D 8F B7 7A 84 B1 F1 77 24 53 85 09 01 1A 42 B4 D0}
    $site_2_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 66 69 6C 65 2E 69 6F 00 00 BA 85 AB 49 49 86 C6 FE 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_2_encoded_base64 = "aHR0cHM6Ly9maWxlLmlv" nocase
    $site_2_encoded_hex = "68747470733a2f2f66696c652e696f" nocase
    $site_2_encoded_rot13 = "uggcf://svyr.vb"
    $site_2_encoded_base32 = "NB2HI4DTHIXS6ZTJNRSS42LP" nocase
    $site_2_encoded_base16 = "68747470733A2F2F66696C652E696F" nocase
    $site_2_encoded_base85 = "XmoUNb2=|CW@&6?E@^K"
    $site_2_encoded_ascii85 = "BQS?8F#ks-Anc'm/no5"
    $site_2_encoded_uu = "aHR0cHM6Ly9maWxlLmlv" nocase
    $site_2_encoded_rot47 = "9EEADi^^7:=6]:@"
    $site_2_encoded_substitution = "kwwsv://iloh.lr"
    $site_2_encoded_caesar = "kwwsv=22iloh1lr"

    $site_3 = "https://sendspace.com" nocase
    $site_3_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4E CD 4B 29 2E 48 4C 4E D5 4B CE CF 05 00 BB 0E 70 8A 15 00 00 00}
    $site_3_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 FF E4 A9 35 00 00 05 19 80 00 01 80 10 2E 43 CC 00 20 00 22 87 A3 44 CD 21 00 00 08 09 13 72 F6 A9 9B 3D 48 67 C5 DC 91 4E 14 24 3F F9 2A 4D 40}
    $site_3_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 73 65 6E 64 73 70 61 63 65 2E 63 6F 6D 00 00 00 00 17 73 C0 0C 6C 29 1C E0 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_3_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4E CD 4B 29 2E 48 4C 4E D5 4B CE CF 05 00 57 9D 07 EF}
    $site_3_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4E CD 4B 29 2E 48 4C 4E D5 4B CE CF 05 00 57 9D 07 EF}
    $site_3_encoded_lz4 = {04 22 4D 18 68 40 15 00 00 00 00 00 00 00 36 15 00 00 80 68 74 74 70 73 3A 2F 2F 73 65 6E 64 73 70 61 63 65 2E 63 6F 6D 00 00 00 00}
    $site_3_encoded_zstd = {28 B5 2F FD 20 15 A9 00 00 68 74 74 70 73 3A 2F 2F 73 65 6E 64 73 70 61 63 65 2E 63 6F 6D}
    $site_3_encoded_snappy = {15 50 68 74 74 70 73 3A 2F 2F 73 65 6E 64 73 70 61 63 65 2E 63 6F 6D}
    $site_3_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 2D 59 A3 90 26 02 03 0B 95 00 04 95 00 B4 83 02 BB 0E 70 8A 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 88 4B D6 03 68 74 74 70 73 3A 2F 2F 73 65 6E 64 73 70 61 63 65 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_3_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4E CD 4B 29 2E 48 4C 4E D5 4B CE CF 05 00 BB 0E 70 8A 15 00 00 00}
    $site_3_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 FF E4 A9 35 00 00 05 19 80 00 01 80 10 2E 43 CC 00 20 00 22 87 A3 44 CD 21 00 00 08 09 13 72 F6 A9 9B 3D 48 67 C5 DC 91 4E 14 24 3F F9 2A 4D 40}
    $site_3_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 73 65 6E 64 73 70 61 63 65 2E 63 6F 6D 00 00 00 00 17 73 C0 0C 6C 29 1C E0 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_3_encoded_base64 = "aHR0cHM6Ly9zZW5kc3BhY2UuY29t" nocase
    $site_3_encoded_hex = "68747470733a2f2f73656e6473706163652e636f6d" nocase
    $site_3_encoded_rot13 = "uggcf://fraqfcnpr.pbz"
    $site_3_encoded_base32 = "NB2HI4DTHIXS643FNZSHG4DBMNSS4Y3PNU======" nocase
    $site_3_encoded_base16 = "68747470733A2F2F73656E6473706163652E636F6D" nocase
    $site_3_encoded_base85 = "XmoUNb2=|Cb7gL1b8ul}WiDfHZ2"
    $site_3_encoded_ascii85 = "BQS?8F#ks-F(K6\"F)YPtAM.J2D#"
    $site_3_encoded_uu = "aHR0cHM6Ly9zZW5kc3BhY2UuY29t" nocase
    $site_3_encoded_rot47 = "9EEADi^^D6?5DA246]4@>"
    $site_3_encoded_substitution = "kwwsv://vhqgvsdfh.frp"
    $site_3_encoded_caesar = "kwwsv=22vhqgvsdfh1frp"

    $site_4 = "https://zerobin.net" nocase
    $site_4_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 AF 4A 2D CA 4F CA CC D3 CB 4B 2D 01 00 1B E1 1F 86 13 00 00 00}
    $site_4_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 4E 39 C5 B0 00 00 03 99 80 00 01 80 10 12 61 DC 10 20 00 22 86 9A 31 A7 AA 10 00 03 CC CA 47 21 49 C4 6B 65 FC 5D C9 14 E1 42 41 38 E7 16 C0}
    $site_4_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 7A 65 72 6F 62 69 6E 2E 6E 65 74 00 00 77 23 D3 ED 22 63 05 B6 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_4_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 AF 4A 2D CA 4F CA CC D3 CB 4B 2D 01 00 48 5B 07 3A}
    $site_4_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 AF 4A 2D CA 4F CA CC D3 CB 4B 2D 01 00 48 5B 07 3A}
    $site_4_encoded_lz4 = {04 22 4D 18 68 40 13 00 00 00 00 00 00 00 FA 13 00 00 80 68 74 74 70 73 3A 2F 2F 7A 65 72 6F 62 69 6E 2E 6E 65 74 00 00 00 00}
    $site_4_encoded_zstd = {28 B5 2F FD 20 13 99 00 00 68 74 74 70 73 3A 2F 2F 7A 65 72 6F 62 69 6E 2E 6E 65 74}
    $site_4_encoded_snappy = {13 48 68 74 74 70 73 3A 2F 2F 7A 65 72 6F 62 69 6E 2E 6E 65 74}
    $site_4_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 AC EA 67 2E 26 02 03 0B 93 00 04 93 00 B4 83 02 1B E1 1F 86 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 6D 55 13 04 68 74 74 70 73 3A 2F 2F 7A 65 72 6F 62 69 6E 2E 6E 65 74 1D 77 56 51 03 05 04 00}
    $site_4_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 AF 4A 2D CA 4F CA CC D3 CB 4B 2D 01 00 1B E1 1F 86 13 00 00 00}
    $site_4_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 4E 39 C5 B0 00 00 03 99 80 00 01 80 10 12 61 DC 10 20 00 22 86 9A 31 A7 AA 10 00 03 CC CA 47 21 49 C4 6B 65 FC 5D C9 14 E1 42 41 38 E7 16 C0}
    $site_4_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 7A 65 72 6F 62 69 6E 2E 6E 65 74 00 00 77 23 D3 ED 22 63 05 B6 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_4_encoded_base64 = "aHR0cHM6Ly96ZXJvYmluLm5ldA==" nocase
    $site_4_encoded_hex = "68747470733a2f2f7a65726f62696e2e6e6574" nocase
    $site_4_encoded_rot13 = "uggcf://mrebova.arg"
    $site_4_encoded_base32 = "NB2HI4DTHIXS66TFOJXWE2LOFZXGK5A=" nocase
    $site_4_encoded_base16 = "68747470733A2F2F7A65726F62696E2E6E6574" nocase
    $site_4_encoded_base85 = "XmoUNb2=|CdS!BNVrgzJZe?@"
    $site_4_encoded_ascii85 = "BQS?8F#ks-H=_,8@VK^4DImn"
    $site_4_encoded_uu = "aHR0cHM6Ly96ZXJvYmluLm5ldA==" nocase
    $site_4_encoded_rot47 = "9EEADi^^K6C@3:?]?6E"
    $site_4_encoded_substitution = "kwwsv://churelq.qhw"
    $site_4_encoded_caesar = "kwwsv=22}hurelq1qhw"

    $site_5 = "https://transfer.sh" nocase
    $site_5_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 29 4A CC 2B 4E 4B 2D D2 2B CE 00 00 5A EE 0B F6 13 00 00 00}
    $site_5_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 83 0F 5C 9D 00 00 04 19 80 00 01 80 10 23 41 5C 00 20 00 22 99 A1 A1 A1 03 40 D0 C0 34 17 F5 95 8C 92 1A 78 5D C9 14 E1 42 42 0C 3D 72 74}
    $site_5_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 74 72 61 6E 73 66 65 72 2E 73 68 00 00 FE E1 6A FF DA FF 7E E4 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_5_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 29 4A CC 2B 4E 4B 2D D2 2B CE 00 00 48 92 07 3A}
    $site_5_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 29 4A CC 2B 4E 4B 2D D2 2B CE 00 00 48 92 07 3A}
    $site_5_encoded_lz4 = {04 22 4D 18 68 40 13 00 00 00 00 00 00 00 FA 13 00 00 80 68 74 74 70 73 3A 2F 2F 74 72 61 6E 73 66 65 72 2E 73 68 00 00 00 00}
    $site_5_encoded_zstd = {28 B5 2F FD 20 13 99 00 00 68 74 74 70 73 3A 2F 2F 74 72 61 6E 73 66 65 72 2E 73 68}
    $site_5_encoded_snappy = {13 48 68 74 74 70 73 3A 2F 2F 74 72 61 6E 73 66 65 72 2E 73 68}
    $site_5_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 7E 96 00 FF 26 02 03 0B 93 00 04 93 00 B4 83 02 5A EE 0B F6 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 3A 69 8D 04 68 74 74 70 73 3A 2F 2F 74 72 61 6E 73 66 65 72 2E 73 68 1D 77 56 51 03 05 04 00}
    $site_5_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 29 4A CC 2B 4E 4B 2D D2 2B CE 00 00 5A EE 0B F6 13 00 00 00}
    $site_5_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 83 0F 5C 9D 00 00 04 19 80 00 01 80 10 23 41 5C 00 20 00 22 99 A1 A1 A1 03 40 D0 C0 34 17 F5 95 8C 92 1A 78 5D C9 14 E1 42 42 0C 3D 72 74}
    $site_5_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 74 72 61 6E 73 66 65 72 2E 73 68 00 00 FE E1 6A FF DA FF 7E E4 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_5_encoded_base64 = "aHR0cHM6Ly90cmFuc2Zlci5zaA==" nocase
    $site_5_encoded_hex = "68747470733a2f2f7472616e736665722e7368" nocase
    $site_5_encoded_rot13 = "uggcf://genafsre.fu"
    $site_5_encoded_base32 = "NB2HI4DTHIXS65DSMFXHGZTFOIXHG2A=" nocase
    $site_5_encoded_base16 = "68747470733A2F2F7472616E736665722E7368" nocase
    $site_5_encoded_base85 = "XmoUNb2=|CbaG*Cb7p07E^}x"
    $site_5_encoded_ascii85 = "BQS?8F#ks-FE1f-F(T!(/ot\\"
    $site_5_encoded_uu = "aHR0cHM6Ly90cmFuc2Zlci5zaA==" nocase
    $site_5_encoded_rot47 = "9EEADi^^EC2?D76C]D9"
    $site_5_encoded_substitution = "kwwsv://wudqvihu.vk"
    $site_5_encoded_caesar = "kwwsv=22wudqvihu1vk"

    $site_6 = "https://filepizza.com" nocase
    $site_6_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB CC 49 2D C8 AC AA 4A D4 4B CE CF 05 00 6E AF 05 7F 15 00 00 00}
    $site_6_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 79 67 39 B4 00 00 04 19 80 00 01 80 10 2B 66 CC 10 20 00 31 4C 00 13 42 87 A9 A0 3C 9A 80 04 E3 D8 3D 95 25 38 B3 3A F8 BB 92 29 C2 84 83 CB 39 CD A0}
    $site_6_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 66 69 6C 65 70 69 7A 7A 61 2E 63 6F 6D 00 00 00 00 76 A5 35 7D 5F 28 F7 18 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_6_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB CC 49 2D C8 AC AA 4A D4 4B CE CF 05 00 57 EA 08 07}
    $site_6_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB CC 49 2D C8 AC AA 4A D4 4B CE CF 05 00 57 EA 08 07}
    $site_6_encoded_lz4 = {04 22 4D 18 68 40 15 00 00 00 00 00 00 00 36 15 00 00 80 68 74 74 70 73 3A 2F 2F 66 69 6C 65 70 69 7A 7A 61 2E 63 6F 6D 00 00 00 00}
    $site_6_encoded_zstd = {28 B5 2F FD 20 15 A9 00 00 68 74 74 70 73 3A 2F 2F 66 69 6C 65 70 69 7A 7A 61 2E 63 6F 6D}
    $site_6_encoded_snappy = {15 50 68 74 74 70 73 3A 2F 2F 66 69 6C 65 70 69 7A 7A 61 2E 63 6F 6D}
    $site_6_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 24 D0 53 AA 26 02 03 0B 95 00 04 95 00 B4 83 02 6E AF 05 7F 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 21 73 CA 04 68 74 74 70 73 3A 2F 2F 66 69 6C 65 70 69 7A 7A 61 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_6_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB CC 49 2D C8 AC AA 4A D4 4B CE CF 05 00 6E AF 05 7F 15 00 00 00}
    $site_6_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 79 67 39 B4 00 00 04 19 80 00 01 80 10 2B 66 CC 10 20 00 31 4C 00 13 42 87 A9 A0 3C 9A 80 04 E3 D8 3D 95 25 38 B3 3A F8 BB 92 29 C2 84 83 CB 39 CD A0}
    $site_6_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 66 69 6C 65 70 69 7A 7A 61 2E 63 6F 6D 00 00 00 00 76 A5 35 7D 5F 28 F7 18 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_6_encoded_base64 = "aHR0cHM6Ly9maWxlcGl6emEuY29t" nocase
    $site_6_encoded_hex = "68747470733a2f2f66696c6570697a7a612e636f6d" nocase
    $site_6_encoded_rot13 = "uggcf://svyrcvmmn.pbz"
    $site_6_encoded_base32 = "NB2HI4DTHIXS6ZTJNRSXA2L2PJQS4Y3PNU======" nocase
    $site_6_encoded_base16 = "68747470733A2F2F66696C6570697A7A612E636F6D" nocase
    $site_6_encoded_base85 = "XmoUNb2=|CW@&6?aA|saVJ>5DZ2"
    $site_6_encoded_ascii85 = "BQS?8F#ks-Anc'mE+sWE@4l&.D#"
    $site_6_encoded_uu = "aHR0cHM6Ly9maWxlcGl6emEuY29t" nocase
    $site_6_encoded_rot47 = "9EEADi^^7:=6A:KK2]4@>"
    $site_6_encoded_substitution = "kwwsv://ilohslccd.frp"
    $site_6_encoded_caesar = "kwwsv=22ilohsl}}d1frp"

    $site_7 = "ngrok.io" nocase
    $site_7_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 4B 2F CA CF D6 CB CC 07 00 12 E4 1C 04 08 00 00 00}
    $site_7_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 73 62 92 7D 00 00 02 11 80 00 01 00 A9 90 00 20 00 22 1A 63 50 86 01 CE B8 07 8B B9 22 9C 28 48 39 B1 49 3E 80}
    $site_7_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 07 6E 67 72 6F 6B 2E 69 6F 00 2D D7 A4 D3 2E AD 10 9E 00 01 20 08 BB 19 D9 BB 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_7_encoded_deflate = {78 9C CB 4B 2F CA CF D6 CB CC 07 00 0E 97 03 28}
    $site_7_encoded_zlib = {78 9C CB 4B 2F CA CF D6 CB CC 07 00 0E 97 03 28}
    $site_7_encoded_lz4 = {04 22 4D 18 68 40 08 00 00 00 00 00 00 00 70 08 00 00 80 6E 67 72 6F 6B 2E 69 6F 00 00 00 00}
    $site_7_encoded_zstd = {28 B5 2F FD 20 08 41 00 00 6E 67 72 6F 6B 2E 69 6F}
    $site_7_encoded_snappy = {08 1C 6E 67 72 6F 6B 2E 69 6F}
    $site_7_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 1A D7 DA 37 26 02 03 0B 88 00 04 88 00 B4 83 02 12 E4 1C 04 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 ED 86 44 05 6E 67 72 6F 6B 2E 69 6F 1D 77 56 51 03 05 04 00}
    $site_7_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 4B 2F CA CF D6 CB CC 07 00 12 E4 1C 04 08 00 00 00}
    $site_7_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 73 62 92 7D 00 00 02 11 80 00 01 00 A9 90 00 20 00 22 1A 63 50 86 01 CE B8 07 8B B9 22 9C 28 48 39 B1 49 3E 80}
    $site_7_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 07 6E 67 72 6F 6B 2E 69 6F 00 2D D7 A4 D3 2E AD 10 9E 00 01 20 08 BB 19 D9 BB 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_7_encoded_base64 = "bmdyb2suaW8=" nocase
    $site_7_encoded_hex = "6e67726f6b2e696f" nocase
    $site_7_encoded_rot13 = "atebx.vb"
    $site_7_encoded_base32 = "NZTXE33LFZUW6===" nocase
    $site_7_encoded_base16 = "6E67726F6B2E696F" nocase
    $site_7_encoded_base85 = "ZfA0DYc6ST"
    $site_7_encoded_ascii85 = "DJ+!.CG'=>"
    $site_7_encoded_uu = "bmdyb2suaW8=" nocase
    $site_7_encoded_rot47 = "?8C@<]:@"
    $site_7_encoded_substitution = "qjurn.lr"
    $site_7_encoded_caesar = "qjurn1lr"

    $site_8 = "https://mixdrop.co" nocase
    $site_8_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF CD AC 48 29 CA 2F D0 4B CE 07 00 F1 DE F3 1A 12 00 00 00}
    $site_8_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 92 C3 9C 86 00 00 03 19 80 00 01 80 10 0C 62 DC 40 20 00 31 00 00 0A 18 8C 9F A9 A9 4C C3 A0 89 B7 41 BB 5F 17 72 45 38 50 90 92 C3 9C 86}
    $site_8_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 11 68 74 74 70 73 3A 2F 2F 6D 69 78 64 72 6F 70 2E 63 6F 00 00 00 2F AD 35 ED 66 78 C5 C9 00 01 2A 12 4B 08 54 BC 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_8_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 CF CD AC 48 29 CA 2F D0 4B CE 07 00 41 20 06 CF}
    $site_8_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 CF CD AC 48 29 CA 2F D0 4B CE 07 00 41 20 06 CF}
    $site_8_encoded_lz4 = {04 22 4D 18 68 40 12 00 00 00 00 00 00 00 D9 12 00 00 80 68 74 74 70 73 3A 2F 2F 6D 69 78 64 72 6F 70 2E 63 6F 00 00 00 00}
    $site_8_encoded_zstd = {28 B5 2F FD 20 12 91 00 00 68 74 74 70 73 3A 2F 2F 6D 69 78 64 72 6F 70 2E 63 6F}
    $site_8_encoded_snappy = {12 44 68 74 74 70 73 3A 2F 2F 6D 69 78 64 72 6F 70 2E 63 6F}
    $site_8_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 27 D8 8C 2A 26 02 03 0B 92 00 04 92 00 B4 83 02 F1 DE F3 1A 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 BB 9A BE 05 68 74 74 70 73 3A 2F 2F 6D 69 78 64 72 6F 70 2E 63 6F 1D 77 56 51 03 05 04 00}
    $site_8_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF CD AC 48 29 CA 2F D0 4B CE 07 00 F1 DE F3 1A 12 00 00 00}
    $site_8_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 92 C3 9C 86 00 00 03 19 80 00 01 80 10 0C 62 DC 40 20 00 31 00 00 0A 18 8C 9F A9 A9 4C C3 A0 89 B7 41 BB 5F 17 72 45 38 50 90 92 C3 9C 86}
    $site_8_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 11 68 74 74 70 73 3A 2F 2F 6D 69 78 64 72 6F 70 2E 63 6F 00 00 00 2F AD 35 ED 66 78 C5 C9 00 01 2A 12 4B 08 54 BC 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_8_encoded_base64 = "aHR0cHM6Ly9taXhkcm9wLmNv" nocase
    $site_8_encoded_hex = "68747470733a2f2f6d697864726f702e636f" nocase
    $site_8_encoded_rot13 = "uggcf://zvkqebc.pb"
    $site_8_encoded_base32 = "NB2HI4DTHIXS63LJPBSHE33QFZRW6===" nocase
    $site_8_encoded_base16 = "68747470733A2F2F6D697864726F702E636F" nocase
    $site_8_encoded_base85 = "XmoUNb2=|CZE1L9a&K@hV{Z"
    $site_8_encoded_ascii85 = "BQS?8F#ks-D/\"6*Ec5nL@rD"
    $site_8_encoded_uu = "aHR0cHM6Ly9taXhkcm9wLmNv" nocase
    $site_8_encoded_rot47 = "9EEADi^^>:I5C@A]4@"
    $site_8_encoded_substitution = "kwwsv://plagurs.fr"
    $site_8_encoded_caesar = "kwwsv=22pl{gurs1fr"

    $site_9 = "https://we.tl" nocase
    $site_9_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4F D5 2B C9 01 00 65 DE D8 AC 0D 00 00 00}
    $site_9_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 93 DD 55 24 00 00 02 99 80 00 01 80 10 02 44 4C 80 20 00 31 00 30 29 9A 1A 7A 89 26 33 C6 C8 F8 5D C9 14 E1 42 42 4F 75 54 90}
    $site_9_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0C 68 74 74 70 73 3A 2F 2F 77 65 2E 74 6C 00 00 00 00 3F 86 3A 69 6D B1 1B 4C 00 01 25 0D 71 19 C4 B6 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_9_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4F D5 2B C9 01 00 22 24 04 B6}
    $site_9_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4F D5 2B C9 01 00 22 24 04 B6}
    $site_9_encoded_lz4 = {04 22 4D 18 68 40 0D 00 00 00 00 00 00 00 8C 0D 00 00 80 68 74 74 70 73 3A 2F 2F 77 65 2E 74 6C 00 00 00 00}
    $site_9_encoded_zstd = {28 B5 2F FD 20 0D 69 00 00 68 74 74 70 73 3A 2F 2F 77 65 2E 74 6C}
    $site_9_encoded_snappy = {0D 30 68 74 74 70 73 3A 2F 2F 77 65 2E 74 6C}
    $site_9_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 80 66 B3 BA 26 02 03 0B 8D 00 04 8D 00 B4 83 02 65 DE D8 AC 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 A0 A4 FB 05 68 74 74 70 73 3A 2F 2F 77 65 2E 74 6C 1D 77 56 51 03 05 04 00}
    $site_9_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4F D5 2B C9 01 00 65 DE D8 AC 0D 00 00 00}
    $site_9_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 93 DD 55 24 00 00 02 99 80 00 01 80 10 02 44 4C 80 20 00 31 00 30 29 9A 1A 7A 89 26 33 C6 C8 F8 5D C9 14 E1 42 42 4F 75 54 90}
    $site_9_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0C 68 74 74 70 73 3A 2F 2F 77 65 2E 74 6C 00 00 00 00 3F 86 3A 69 6D B1 1B 4C 00 01 25 0D 71 19 C4 B6 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_9_encoded_base64 = "aHR0cHM6Ly93ZS50bA==" nocase
    $site_9_encoded_hex = "68747470733a2f2f77652e746c" nocase
    $site_9_encoded_rot13 = "uggcf://jr.gy"
    $site_9_encoded_base32 = "NB2HI4DTHIXS653FFZ2GY===" nocase
    $site_9_encoded_base16 = "68747470733A2F2F77652E746C" nocase
    $site_9_encoded_base85 = "XmoUNb2=|CcV#YgYy"
    $site_9_encoded_ascii85 = "BQS?8F#ks-G@`CKC]"
    $site_9_encoded_uu = "aHR0cHM6Ly93ZS50bA==" nocase
    $site_9_encoded_rot47 = "9EEADi^^H6]E="
    $site_9_encoded_substitution = "kwwsv://zh.wo"
    $site_9_encoded_caesar = "kwwsv=22zh1wo"

    $site_10 = "https://0x0.st" nocase
    $site_10_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 37 A8 30 D0 2B 2E 01 00 12 FB 84 2E 0E 00 00 00}
    $site_10_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 88 C1 6D 21 00 00 03 19 80 00 01 C0 10 00 40 4C 40 20 00 22 06 86 D4 20 C9 88 B4 8A 64 0D 20 F1 77 24 53 85 09 08 8C 16 D2 10}
    $site_10_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0D 68 74 74 70 73 3A 2F 2F 30 78 30 2E 73 74 00 00 00 7D 3E B0 1D FE 80 2B B4 00 01 26 0E 08 1B E0 04 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_10_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 37 A8 30 D0 2B 2E 01 00 25 47 04 B9}
    $site_10_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 37 A8 30 D0 2B 2E 01 00 25 47 04 B9}
    $site_10_encoded_lz4 = {04 22 4D 18 68 40 0E 00 00 00 00 00 00 00 C2 0E 00 00 80 68 74 74 70 73 3A 2F 2F 30 78 30 2E 73 74 00 00 00 00}
    $site_10_encoded_zstd = {28 B5 2F FD 20 0E 71 00 00 68 74 74 70 73 3A 2F 2F 30 78 30 2E 73 74}
    $site_10_encoded_snappy = {0E 34 68 74 74 70 73 3A 2F 2F 30 78 30 2E 73 74}
    $site_10_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 BC 14 D4 25 26 02 03 0B 8E 00 04 8E 00 B4 83 02 12 FB 84 2E 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 6D B8 75 06 68 74 74 70 73 3A 2F 2F 30 78 30 2E 73 74 1D 77 56 51 03 05 04 00}
    $site_10_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 37 A8 30 D0 2B 2E 01 00 12 FB 84 2E 0E 00 00 00}
    $site_10_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 88 C1 6D 21 00 00 03 19 80 00 01 C0 10 00 40 4C 40 20 00 22 06 86 D4 20 C9 88 B4 8A 64 0D 20 F1 77 24 53 85 09 08 8C 16 D2 10}
    $site_10_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0D 68 74 74 70 73 3A 2F 2F 30 78 30 2E 73 74 00 00 00 7D 3E B0 1D FE 80 2B B4 00 01 26 0E 08 1B E0 04 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_10_encoded_base64 = "aHR0cHM6Ly8weDAuc3Q=" nocase
    $site_10_encoded_hex = "68747470733a2f2f3078302e7374" nocase
    $site_10_encoded_rot13 = "uggcf://0k0.fg"
    $site_10_encoded_base32 = "NB2HI4DTHIXS6MDYGAXHG5A=" nocase
    $site_10_encoded_base16 = "68747470733A2F2F3078302E7374" nocase
    $site_10_encoded_base85 = "XmoUNb2=|CFnBO7b94"
    $site_10_encoded_ascii85 = "BQS?8F#ks-0R,9(F*%"
    $site_10_encoded_uu = "aHR0cHM6Ly8weDAuc3Q=" nocase
    $site_10_encoded_rot5 = "https://5x5.st"
    $site_10_encoded_rot18 = "https://2x2.st"
    $site_10_encoded_rot47 = "9EEADi^^_I_]DE"
    $site_10_encoded_substitution = "kwwsv://0a0.vw"
    $site_10_encoded_caesar = "kwwsv=223{31vw"

    $site_11 = "https://toptal.com/developers/hastebin" nocase
    $site_11_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F C9 2F 28 49 CC D1 4B CE CF D5 4F 49 2D 4B CD C9 2F 48 2D 2A D6 CF 48 2C 2E 49 4D CA CC 03 00 C5 09 6E E9 26 00 00 00}
    $site_11_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 9D D4 62 DD 00 00 08 19 80 00 01 80 10 3E 67 DD 00 20 00 31 4C 98 99 06 46 14 D1 90 1E A6 9B 51 AA EE 19 08 18 65 F1 75 87 7C 92 48 54 46 F0 C2 40 BC 5F E2 EE 48 A7 0A 12 13 BA 8C 5B A0}
    $site_11_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 25 68 74 74 70 73 3A 2F 2F 74 6F 70 74 61 6C 2E 63 6F 6D 2F 64 65 76 65 6C 6F 70 65 72 73 2F 68 61 73 74 65 62 69 6E 00 00 00 DE C4 83 5C 58 F7 73 FF 00 01 3E 26 AB 2B 4E B3 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_11_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F C9 2F 28 49 CC D1 4B CE CF D5 4F 49 2D 4B CD C9 2F 48 2D 2A D6 CF 48 2C 2E 49 4D CA CC 03 00 1A 23 0E B2}
    $site_11_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F C9 2F 28 49 CC D1 4B CE CF D5 4F 49 2D 4B CD C9 2F 48 2D 2A D6 CF 48 2C 2E 49 4D CA CC 03 00 1A 23 0E B2}
    $site_11_encoded_lz4 = {04 22 4D 18 68 40 26 00 00 00 00 00 00 00 85 26 00 00 80 68 74 74 70 73 3A 2F 2F 74 6F 70 74 61 6C 2E 63 6F 6D 2F 64 65 76 65 6C 6F 70 65 72 73 2F 68 61 73 74 65 62 69 6E 00 00 00 00}
    $site_11_encoded_zstd = {28 B5 2F FD 20 26 31 01 00 68 74 74 70 73 3A 2F 2F 74 6F 70 74 61 6C 2E 63 6F 6D 2F 64 65 76 65 6C 6F 70 65 72 73 2F 68 61 73 74 65 62 69 6E}
    $site_11_encoded_snappy = {26 94 68 74 74 70 73 3A 2F 2F 74 6F 70 74 61 6C 2E 63 6F 6D 2F 64 65 76 65 6C 6F 70 65 72 73 2F 68 61 73 74 65 62 69 6E}
    $site_11_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 76 BF E2 AF 26 02 03 0B A6 00 04 A6 00 B4 83 02 C5 09 6E E9 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 54 C2 B2 06 68 74 74 70 73 3A 2F 2F 74 6F 70 74 61 6C 2E 63 6F 6D 2F 64 65 76 65 6C 6F 70 65 72 73 2F 68 61 73 74 65 62 69 6E 1D 77 56 51 03 05 04 00}
    $site_11_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F C9 2F 28 49 CC D1 4B CE CF D5 4F 49 2D 4B CD C9 2F 48 2D 2A D6 CF 48 2C 2E 49 4D CA CC 03 00 C5 09 6E E9 26 00 00 00}
    $site_11_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 9D D4 62 DD 00 00 08 19 80 00 01 80 10 3E 67 DD 00 20 00 31 4C 98 99 06 46 14 D1 90 1E A6 9B 51 AA EE 19 08 18 65 F1 75 87 7C 92 48 54 46 F0 C2 40 BC 5F E2 EE 48 A7 0A 12 13 BA 8C 5B A0}
    $site_11_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 25 68 74 74 70 73 3A 2F 2F 74 6F 70 74 61 6C 2E 63 6F 6D 2F 64 65 76 65 6C 6F 70 65 72 73 2F 68 61 73 74 65 62 69 6E 00 00 00 DE C4 83 5C 58 F7 73 FF 00 01 3E 26 AB 2B 4E B3 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_11_encoded_base64 = "aHR0cHM6Ly90b3B0YWwuY29tL2RldmVsb3BlcnMvaGFzdGViaW4=" nocase
    $site_11_encoded_hex = "68747470733a2f2f746f7074616c2e636f6d2f646576656c6f706572732f686173746562696e" nocase
    $site_11_encoded_rot13 = "uggcf://gbcgny.pbz/qrirybcref/unfgrova"
    $site_11_encoded_base32 = "NB2HI4DTHIXS65DPOB2GC3BOMNXW2L3EMV3GK3DPOBSXE4ZPNBQXG5DFMJUW4===" nocase
    $site_11_encoded_base16 = "68747470733A2F2F746F7074616C2E636F6D2F646576656C6F706572732F686173746562696E" nocase
    $site_11_encoded_base85 = "XmoUNb2=|CbZ>BUVQemAZ*4DRWp-t3Z*XODb1!INb97~5X>I"
    $site_11_encoded_ascii85 = "BQS?8F#ks-FDl,?@;IQ+Df%.<AThX$DfB9.F\"_38F*(u&Bl3"
    $site_11_encoded_uu = "aHR0cHM6Ly90b3B0YWwuY29tL2RldmVsb3BlcnMvaGFzdGViaW4=" nocase
    $site_11_encoded_rot47 = "9EEADi^^E@AE2=]4@>^56G6=@A6CD^92DE63:?"
    $site_11_encoded_substitution = "kwwsv://wrswdo.frp/ghyhorshuv/kdvwhelq"
    $site_11_encoded_caesar = "kwwsv=22wrswdo1frp2ghyhorshuv2kdvwhelq"

    $site_12 = "https://bayfiles.com" nocase
    $site_12_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 4A AC 4C CB CC 49 2D D6 4B CE CF 05 00 14 A6 D5 16 14 00 00 00}
    $site_12_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 72 6E 53 AF 00 00 04 99 80 00 01 80 10 3B 66 CC 20 20 00 22 8F 48 06 35 3D 42 86 9A 60 00 B3 0C 0B BA 97 93 08 A0 97 C5 DC 91 4E 14 24 1C 9B 94 EB C0}
    $site_12_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 62 61 79 66 69 6C 65 73 2E 63 6F 6D 00 00 09 14 DF E3 B7 E6 4C 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_12_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 4A AC 4C CB CC 49 2D D6 4B CE CF 05 00 4F 0B 07 88}
    $site_12_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 4A AC 4C CB CC 49 2D D6 4B CE CF 05 00 4F 0B 07 88}
    $site_12_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 62 61 79 66 69 6C 65 73 2E 63 6F 6D 00 00 00 00}
    $site_12_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 62 61 79 66 69 6C 65 73 2E 63 6F 6D}
    $site_12_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 62 61 79 66 69 6C 65 73 2E 63 6F 6D}
    $site_12_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 C3 D2 97 4A 26 02 03 0B 94 00 04 94 00 B4 83 02 14 A6 D5 16 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 20 D6 2C 07 68 74 74 70 73 3A 2F 2F 62 61 79 66 69 6C 65 73 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_12_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 4A AC 4C CB CC 49 2D D6 4B CE CF 05 00 14 A6 D5 16 14 00 00 00}
    $site_12_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 72 6E 53 AF 00 00 04 99 80 00 01 80 10 3B 66 CC 20 20 00 22 8F 48 06 35 3D 42 86 9A 60 00 B3 0C 0B BA 97 93 08 A0 97 C5 DC 91 4E 14 24 1C 9B 94 EB C0}
    $site_12_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 62 61 79 66 69 6C 65 73 2E 63 6F 6D 00 00 09 14 DF E3 B7 E6 4C 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_12_encoded_base64 = "aHR0cHM6Ly9iYXlmaWxlcy5jb20=" nocase
    $site_12_encoded_hex = "68747470733a2f2f62617966696c65732e636f6d" nocase
    $site_12_encoded_rot13 = "uggcf://onlsvyrf.pbz"
    $site_12_encoded_base32 = "NB2HI4DTHIXS6YTBPFTGS3DFOMXGG33N" nocase
    $site_12_encoded_base16 = "68747470733A2F2F62617966696C65732E636F6D" nocase
    $site_12_encoded_base85 = "XmoUNb2=|CVqtk^X>4V4E@N+P"
    $site_12_encoded_ascii85 = "BQS?8F#ks-@UXOoBl%@%/n8g:"
    $site_12_encoded_uu = "aHR0cHM6Ly9iYXlmaWxlcy5jb20=" nocase
    $site_12_encoded_rot47 = "9EEADi^^32J7:=6D]4@>"
    $site_12_encoded_substitution = "kwwsv://edbilohv.frp"
    $site_12_encoded_caesar = "kwwsv=22ed|ilohv1frp"

    $site_13 = "https://p.ip.fi" nocase
    $site_13_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F D0 CB 2C D0 4B CB 04 00 4A 45 66 89 0F 00 00 00}
    $site_13_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 58 CD EF 0F 00 00 03 19 80 00 01 80 10 01 60 4C 00 20 00 22 06 4C 42 0C 98 85 40 32 D6 E9 8F 27 8B B9 22 9C 28 48 2C 66 F7 87 80}
    $site_13_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 70 2E 69 70 2E 66 69 00 00 7C 9A D9 6A 47 A5 08 FA 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_13_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F D0 CB 2C D0 4B CB 04 00 2B A7 05 40}
    $site_13_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F D0 CB 2C D0 4B CB 04 00 2B A7 05 40}
    $site_13_encoded_lz4 = {04 22 4D 18 68 40 0F 00 00 00 00 00 00 00 16 0F 00 00 80 68 74 74 70 73 3A 2F 2F 70 2E 69 70 2E 66 69 00 00 00 00}
    $site_13_encoded_zstd = {28 B5 2F FD 20 0F 79 00 00 68 74 74 70 73 3A 2F 2F 70 2E 69 70 2E 66 69}
    $site_13_encoded_snappy = {0F 38 68 74 74 70 73 3A 2F 2F 70 2E 69 70 2E 66 69}
    $site_13_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 63 06 C8 C3 26 02 03 0B 8F 00 04 8F 00 B4 83 02 4A 45 66 89 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 EE E9 A6 07 68 74 74 70 73 3A 2F 2F 70 2E 69 70 2E 66 69 1D 77 56 51 03 05 04 00}
    $site_13_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F D0 CB 2C D0 4B CB 04 00 4A 45 66 89 0F 00 00 00}
    $site_13_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 58 CD EF 0F 00 00 03 19 80 00 01 80 10 01 60 4C 00 20 00 22 06 4C 42 0C 98 85 40 32 D6 E9 8F 27 8B B9 22 9C 28 48 2C 66 F7 87 80}
    $site_13_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 70 2E 69 70 2E 66 69 00 00 7C 9A D9 6A 47 A5 08 FA 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_13_encoded_base64 = "aHR0cHM6Ly9wLmlwLmZp" nocase
    $site_13_encoded_hex = "68747470733a2f2f702e69702e6669" nocase
    $site_13_encoded_rot13 = "uggcf://c.vc.sv"
    $site_13_encoded_base32 = "NB2HI4DTHIXS64BONFYC4ZTJ" nocase
    $site_13_encoded_base16 = "68747470733A2F2F702E69702E6669" nocase
    $site_13_encoded_base85 = "XmoUNb2=|Ca4u<ZE@o)"
    $site_13_encoded_ascii85 = "BQS?8F#ks-E%YjD/nSe"
    $site_13_encoded_uu = "aHR0cHM6Ly9wLmlwLmZp" nocase
    $site_13_encoded_rot47 = "9EEADi^^A]:A]7:"
    $site_13_encoded_substitution = "kwwsv://s.ls.il"
    $site_13_encoded_caesar = "kwwsv=22s1ls1il"

    $site_14 = "https://filebin.net" nocase
    $site_14_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB CC 49 4D CA CC D3 CB 4B 2D 01 00 B2 D2 0D CD 13 00 00 00}
    $site_14_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 18 64 25 97 00 00 04 19 80 00 01 80 10 13 65 4C 00 20 00 31 00 D0 01 4C 03 46 81 9B 67 21 C8 1B EC 72 14 F0 BB 92 29 C2 84 80 C3 21 2C B8}
    $site_14_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 66 69 6C 65 62 69 6E 2E 6E 65 74 00 00 1F 14 1D 5D 7C 37 A7 CB 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_14_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB CC 49 4D CA CC D3 CB 4B 2D 01 00 47 21 07 1A}
    $site_14_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB CC 49 4D CA CC D3 CB 4B 2D 01 00 47 21 07 1A}
    $site_14_encoded_lz4 = {04 22 4D 18 68 40 13 00 00 00 00 00 00 00 FA 13 00 00 80 68 74 74 70 73 3A 2F 2F 66 69 6C 65 62 69 6E 2E 6E 65 74 00 00 00 00}
    $site_14_encoded_zstd = {28 B5 2F FD 20 13 99 00 00 68 74 74 70 73 3A 2F 2F 66 69 6C 65 62 69 6E 2E 6E 65 74}
    $site_14_encoded_snappy = {13 48 68 74 74 70 73 3A 2F 2F 66 69 6C 65 62 69 6E 2E 6E 65 74}
    $site_14_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 FB E1 35 BE 26 02 03 0B 93 00 04 93 00 B4 83 02 B2 D2 0D CD 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 D3 F3 E3 07 68 74 74 70 73 3A 2F 2F 66 69 6C 65 62 69 6E 2E 6E 65 74 1D 77 56 51 03 05 04 00}
    $site_14_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB CC 49 4D CA CC D3 CB 4B 2D 01 00 B2 D2 0D CD 13 00 00 00}
    $site_14_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 18 64 25 97 00 00 04 19 80 00 01 80 10 13 65 4C 00 20 00 31 00 D0 01 4C 03 46 81 9B 67 21 C8 1B EC 72 14 F0 BB 92 29 C2 84 80 C3 21 2C B8}
    $site_14_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 66 69 6C 65 62 69 6E 2E 6E 65 74 00 00 1F 14 1D 5D 7C 37 A7 CB 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_14_encoded_base64 = "aHR0cHM6Ly9maWxlYmluLm5ldA==" nocase
    $site_14_encoded_hex = "68747470733a2f2f66696c6562696e2e6e6574" nocase
    $site_14_encoded_rot13 = "uggcf://svyrova.arg"
    $site_14_encoded_base32 = "NB2HI4DTHIXS6ZTJNRSWE2LOFZXGK5A=" nocase
    $site_14_encoded_base16 = "68747470733A2F2F66696C6562696E2E6E6574" nocase
    $site_14_encoded_base85 = "XmoUNb2=|CW@&6?VrgzJZe?@"
    $site_14_encoded_ascii85 = "BQS?8F#ks-Anc'm@VK^4DImn"
    $site_14_encoded_uu = "aHR0cHM6Ly9maWxlYmluLm5ldA==" nocase
    $site_14_encoded_rot47 = "9EEADi^^7:=63:?]?6E"
    $site_14_encoded_substitution = "kwwsv://ilohelq.qhw"
    $site_14_encoded_caesar = "kwwsv=22ilohelq1qhw"

    $site_15 = "cdn.discordapp.com/attachments" nocase
    $site_15_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF 4B 4E C9 D3 4B C9 2C 4E CE 2F 4A 49 2C 28 D0 4B CE CF D5 4F 2C 29 49 4C CE C8 4D CD 2B 29 06 00 74 C6 58 25 1E 00 00 00}
    $site_15_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 8C 0D B2 0D 00 00 03 11 80 00 01 AE 63 DC 00 20 00 22 99 34 D3 D4 F5 33 50 A6 00 03 C4 A1 28 07 4E 43 71 5B DC 62 CC D2 65 1F 17 72 45 38 50 90 8C 0D B2 0D}
    $site_15_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 1D 63 64 6E 2E 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 74 74 61 63 68 6D 65 6E 74 73 00 00 00 F4 7B 21 DA B0 63 4C 17 00 01 36 1E 3D 19 95 53 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_15_encoded_deflate = {78 9C 4B 4E C9 D3 4B C9 2C 4E CE 2F 4A 49 2C 28 D0 4B CE CF D5 4F 2C 29 49 4C CE C8 4D CD 2B 29 06 00 B3 05 0B C5}
    $site_15_encoded_zlib = {78 9C 4B 4E C9 D3 4B C9 2C 4E CE 2F 4A 49 2C 28 D0 4B CE CF D5 4F 2C 29 49 4C CE C8 4D CD 2B 29 06 00 B3 05 0B C5}
    $site_15_encoded_lz4 = {04 22 4D 18 68 40 1E 00 00 00 00 00 00 00 89 1E 00 00 80 63 64 6E 2E 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 74 74 61 63 68 6D 65 6E 74 73 00 00 00 00}
    $site_15_encoded_zstd = {28 B5 2F FD 20 1E F1 00 00 63 64 6E 2E 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 74 74 61 63 68 6D 65 6E 74 73}
    $site_15_encoded_snappy = {1E 74 63 64 6E 2E 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 74 74 61 63 68 6D 65 6E 74 73}
    $site_15_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 3C F6 1B A0 26 02 03 0B 9E 00 04 9E 00 B4 83 02 74 C6 58 25 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 A0 07 5E 08 63 64 6E 2E 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 74 74 61 63 68 6D 65 6E 74 73 1D 77 56 51 03 05 04 00}
    $site_15_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF 4B 4E C9 D3 4B C9 2C 4E CE 2F 4A 49 2C 28 D0 4B CE CF D5 4F 2C 29 49 4C CE C8 4D CD 2B 29 06 00 74 C6 58 25 1E 00 00 00}
    $site_15_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 8C 0D B2 0D 00 00 03 11 80 00 01 AE 63 DC 00 20 00 22 99 34 D3 D4 F5 33 50 A6 00 03 C4 A1 28 07 4E 43 71 5B DC 62 CC D2 65 1F 17 72 45 38 50 90 8C 0D B2 0D}
    $site_15_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 1D 63 64 6E 2E 64 69 73 63 6F 72 64 61 70 70 2E 63 6F 6D 2F 61 74 74 61 63 68 6D 65 6E 74 73 00 00 00 F4 7B 21 DA B0 63 4C 17 00 01 36 1E 3D 19 95 53 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_15_encoded_base64 = "Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz" nocase
    $site_15_encoded_hex = "63646e2e646973636f72646170702e636f6d2f6174746163686d656e7473" nocase
    $site_15_encoded_rot13 = "pqa.qvfpbeqncc.pbz/nggnpuzragf"
    $site_15_encoded_base32 = "MNSG4LTENFZWG33SMRQXA4BOMNXW2L3BOR2GCY3INVSW45DT" nocase
    $site_15_encoded_base16 = "63646E2E646973636F72646170702E636F6D2F6174746163686D656E7473" nocase
    $site_15_encoded_base85 = "V`OeFWNC9_Z*pW|aBwbTZ*4DObaY{3Xl-R~baM"
    $site_15_encoded_ascii85 = "@q9I0A8-*pDfTAsE,[F>Df%.9FECr$BPh<uFE7"
    $site_15_encoded_uu = "Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz" nocase
    $site_15_encoded_rot47 = "45?]5:D4@C52AA]4@>^2EE249>6?ED"
    $site_15_encoded_substitution = "fgq.glvfrugdss.frp/dwwdfkphqwv"
    $site_15_encoded_caesar = "fgq1glvfrugdss1frp2dwwdfkphqwv"

    $site_16 = "https://ctrlv.it" nocase
    $site_16_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 2E 29 CA 29 D3 CB 2C 01 00 BC 67 4A DA 10 00 00 00}
    $site_16_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 08 D5 59 49 00 00 02 99 80 00 01 80 10 08 64 5D 00 20 00 22 13 02 3D AA 10 34 0D 02 65 70 B2 18 51 E4 7C 5D C9 14 E1 42 40 23 55 65 24}
    $site_16_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 63 74 72 6C 76 2E 69 74 00 FF 34 D6 08 2F E8 FA E8 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_16_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 2E 29 CA 29 D3 CB 2C 01 00 33 77 06 02}
    $site_16_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 2E 29 CA 29 D3 CB 2C 01 00 33 77 06 02}
    $site_16_encoded_lz4 = {04 22 4D 18 68 40 10 00 00 00 00 00 00 00 65 10 00 00 80 68 74 74 70 73 3A 2F 2F 63 74 72 6C 76 2E 69 74 00 00 00 00}
    $site_16_encoded_zstd = {28 B5 2F FD 20 10 81 00 00 68 74 74 70 73 3A 2F 2F 63 74 72 6C 76 2E 69 74}
    $site_16_encoded_snappy = {10 3C 68 74 74 70 73 3A 2F 2F 63 74 72 6C 76 2E 69 74}
    $site_16_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 D8 12 B7 9A 26 02 03 0B 90 00 04 90 00 B4 83 02 BC 67 4A DA 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 87 11 9B 08 68 74 74 70 73 3A 2F 2F 63 74 72 6C 76 2E 69 74 1D 77 56 51 03 05 04 00}
    $site_16_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 2E 29 CA 29 D3 CB 2C 01 00 BC 67 4A DA 10 00 00 00}
    $site_16_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 08 D5 59 49 00 00 02 99 80 00 01 80 10 08 64 5D 00 20 00 22 13 02 3D AA 10 34 0D 02 65 70 B2 18 51 E4 7C 5D C9 14 E1 42 40 23 55 65 24}
    $site_16_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 63 74 72 6C 76 2E 69 74 00 FF 34 D6 08 2F E8 FA E8 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_16_encoded_base64 = "aHR0cHM6Ly9jdHJsdi5pdA==" nocase
    $site_16_encoded_hex = "68747470733a2f2f6374726c762e6974" nocase
    $site_16_encoded_rot13 = "uggcf://pgeyi.vg"
    $site_16_encoded_base32 = "NB2HI4DTHIXS6Y3UOJWHMLTJOQ======" nocase
    $site_16_encoded_base16 = "68747470733A2F2F6374726C762E6974" nocase
    $site_16_encoded_base85 = "XmoUNb2=|CV{~$Cb}ngj"
    $site_16_encoded_ascii85 = "BQS?8F#ks-@rua-FtRKN"
    $site_16_encoded_uu = "aHR0cHM6Ly9jdHJsdi5pdA==" nocase
    $site_16_encoded_rot47 = "9EEADi^^4EC=G]:E"
    $site_16_encoded_substitution = "kwwsv://fwuoy.lw"
    $site_16_encoded_caesar = "kwwsv=22fwuoy1lw"

    $site_17 = "https://controlc.com" nocase
    $site_17_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CE CF 2B 29 CA CF 49 D6 4B CE CF 05 00 B1 C0 94 CF 14 00 00 00}
    $site_17_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 E6 10 C5 78 00 00 03 99 80 00 01 80 10 08 47 DC 00 20 00 22 26 9E 80 34 20 1A 00 00 6C 38 9B F6 D2 14 2A 4F 0B B9 22 9C 28 48 73 08 62 BC 00}
    $site_17_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 63 6F 6E 74 72 6F 6C 63 2E 63 6F 6D 00 8C 38 D0 FF CF E5 9B 2B 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_17_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CE CF 2B 29 CA CF 49 D6 4B CE CF 05 00 4F F8 07 9D}
    $site_17_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CE CF 2B 29 CA CF 49 D6 4B CE CF 05 00 4F F8 07 9D}
    $site_17_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 63 6F 6E 74 72 6F 6C 63 2E 63 6F 6D 00 00 00 00}
    $site_17_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 63 6F 6E 74 72 6F 6C 63 2E 63 6F 6D}
    $site_17_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 63 6F 6E 74 72 6F 6C 63 2E 63 6F 6D}
    $site_17_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 EF EE E0 6D 26 02 03 0B 94 00 04 94 00 B4 83 02 B1 C0 94 CF 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 53 25 15 09 68 74 74 70 73 3A 2F 2F 63 6F 6E 74 72 6F 6C 63 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_17_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CE CF 2B 29 CA CF 49 D6 4B CE CF 05 00 B1 C0 94 CF 14 00 00 00}
    $site_17_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 E6 10 C5 78 00 00 03 99 80 00 01 80 10 08 47 DC 00 20 00 22 26 9E 80 34 20 1A 00 00 6C 38 9B F6 D2 14 2A 4F 0B B9 22 9C 28 48 73 08 62 BC 00}
    $site_17_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 63 6F 6E 74 72 6F 6C 63 2E 63 6F 6D 00 8C 38 D0 FF CF E5 9B 2B 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_17_encoded_base64 = "aHR0cHM6Ly9jb250cm9sYy5jb20=" nocase
    $site_17_encoded_hex = "68747470733a2f2f636f6e74726f6c632e636f6d" nocase
    $site_17_encoded_rot13 = "uggcf://pbagebyp.pbz"
    $site_17_encoded_base32 = "NB2HI4DTHIXS6Y3PNZ2HE33MMMXGG33N" nocase
    $site_17_encoded_base16 = "68747470733A2F2F636F6E74726F6C632E636F6D" nocase
    $site_17_encoded_base85 = "XmoUNb2=|CV{dMBa&K&7E@N+P"
    $site_17_encoded_ascii85 = "BQS?8F#ks-@rH7,Ec5c(/n8g:"
    $site_17_encoded_uu = "aHR0cHM6Ly9jb250cm9sYy5jb20=" nocase
    $site_17_encoded_rot47 = "9EEADi^^4@?EC@=4]4@>"
    $site_17_encoded_substitution = "kwwsv://frqwurof.frp"
    $site_17_encoded_caesar = "kwwsv=22frqwurof1frp"

    $site_18 = "https://discord.com/api" nocase
    $site_18_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F C9 2C 4E CE 2F 4A D1 4B CE CF D5 4F 2C C8 04 00 2B AB D8 1A 17 00 00 00}
    $site_18_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 EE 40 86 7F 00 00 05 19 80 00 01 80 10 2C 62 DC 00 20 00 22 8D A6 93 4C D2 10 00 00 89 75 C2 C8 52 95 7A BC 06 06 7C 5D C9 14 E1 42 43 B9 02 19 FC}
    $site_18_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 16 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 00 00 68 D6 B4 B7 F6 EC 6F F4 00 01 2F 17 81 08 49 B1 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_18_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F C9 2C 4E CE 2F 4A D1 4B CE CF D5 4F 2C C8 04 00 67 31 08 8A}
    $site_18_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F C9 2C 4E CE 2F 4A D1 4B CE CF D5 4F 2C C8 04 00 67 31 08 8A}
    $site_18_encoded_lz4 = {04 22 4D 18 68 40 17 00 00 00 00 00 00 00 32 17 00 00 80 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 00 00 00 00}
    $site_18_encoded_zstd = {28 B5 2F FD 20 17 B9 00 00 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69}
    $site_18_encoded_snappy = {17 58 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69}
    $site_18_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 1B F9 B2 78 26 02 03 0B 97 00 04 97 00 B4 83 02 2B AB D8 1A 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 3A 2F 52 09 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 1D 77 56 51 03 05 04 00}
    $site_18_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F C9 2C 4E CE 2F 4A D1 4B CE CF D5 4F 2C C8 04 00 2B AB D8 1A 17 00 00 00}
    $site_18_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 EE 40 86 7F 00 00 05 19 80 00 01 80 10 2C 62 DC 00 20 00 22 8D A6 93 4C D2 10 00 00 89 75 C2 C8 52 95 7A BC 06 06 7C 5D C9 14 E1 42 43 B9 02 19 FC}
    $site_18_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 16 68 74 74 70 73 3A 2F 2F 64 69 73 63 6F 72 64 2E 63 6F 6D 2F 61 70 69 00 00 68 D6 B4 B7 F6 EC 6F F4 00 01 2F 17 81 08 49 B1 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_18_encoded_base64 = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGk=" nocase
    $site_18_encoded_hex = "68747470733a2f2f646973636f72642e636f6d2f617069" nocase
    $site_18_encoded_rot13 = "uggcf://qvfpbeq.pbz/ncv"
    $site_18_encoded_base32 = "NB2HI4DTHIXS6ZDJONRW64TEFZRW63JPMFYGS===" nocase
    $site_18_encoded_base16 = "68747470733A2F2F646973636F72642E636F6D2F617069" nocase
    $site_18_encoded_base85 = "XmoUNb2=|CWNC9_Z*pWVV{dIQVQ^^"
    $site_18_encoded_ascii85 = "BQS?8F#ks-A8-*pDfTA@@rH3;@;oo"
    $site_18_encoded_uu = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGk=" nocase
    $site_18_encoded_rot47 = "9EEADi^^5:D4@C5]4@>^2A:"
    $site_18_encoded_substitution = "kwwsv://glvfrug.frp/dsl"
    $site_18_encoded_caesar = "kwwsv=22glvfrug1frp2dsl"

    $site_19 = "https://uploadfiles.io" nocase
    $site_19_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 2D C8 C9 4F 4C 49 CB CC 49 2D D6 CB CC 07 00 E9 97 05 FC 16 00 00 00}
    $site_19_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 C0 BF E8 98 00 00 04 19 80 00 01 80 10 27 64 CE 00 20 00 22 8F 29 A0 7A 35 0A 60 00 24 90 A1 6C F7 8A 74 1B A8 0E BE 2E E4 8A 70 A1 21 81 7F D1 30}
    $site_19_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 15 68 74 74 70 73 3A 2F 2F 75 70 6C 6F 61 64 66 69 6C 65 73 2E 69 6F 00 00 00 92 E9 70 19 35 D2 5C DE 00 01 2E 16 56 09 55 DF 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_19_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 2D C8 C9 4F 4C 49 CB CC 49 2D D6 CB CC 07 00 60 EB 08 6A}
    $site_19_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 2D C8 C9 4F 4C 49 CB CC 49 2D D6 CB CC 07 00 60 EB 08 6A}
    $site_19_encoded_lz4 = {04 22 4D 18 68 40 16 00 00 00 00 00 00 00 E8 16 00 00 80 68 74 74 70 73 3A 2F 2F 75 70 6C 6F 61 64 66 69 6C 65 73 2E 69 6F 00 00 00 00}
    $site_19_encoded_zstd = {28 B5 2F FD 20 16 B1 00 00 68 74 74 70 73 3A 2F 2F 75 70 6C 6F 61 64 66 69 6C 65 73 2E 69 6F}
    $site_19_encoded_snappy = {16 54 68 74 74 70 73 3A 2F 2F 75 70 6C 6F 61 64 66 69 6C 65 73 2E 69 6F}
    $site_19_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 11 A4 AC 48 26 02 03 0B 96 00 04 96 00 B4 83 02 E9 97 05 FC 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 07 43 CC 09 68 74 74 70 73 3A 2F 2F 75 70 6C 6F 61 64 66 69 6C 65 73 2E 69 6F 1D 77 56 51 03 05 04 00}
    $site_19_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 2D C8 C9 4F 4C 49 CB CC 49 2D D6 CB CC 07 00 E9 97 05 FC 16 00 00 00}
    $site_19_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 C0 BF E8 98 00 00 04 19 80 00 01 80 10 27 64 CE 00 20 00 22 8F 29 A0 7A 35 0A 60 00 24 90 A1 6C F7 8A 74 1B A8 0E BE 2E E4 8A 70 A1 21 81 7F D1 30}
    $site_19_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 15 68 74 74 70 73 3A 2F 2F 75 70 6C 6F 61 64 66 69 6C 65 73 2E 69 6F 00 00 00 92 E9 70 19 35 D2 5C DE 00 01 2E 16 56 09 55 DF 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_19_encoded_base64 = "aHR0cHM6Ly91cGxvYWRmaWxlcy5pbw==" nocase
    $site_19_encoded_hex = "68747470733a2f2f75706c6f616466696c65732e696f" nocase
    $site_19_encoded_rot13 = "uggcf://hcybnqsvyrf.vb"
    $site_19_encoded_base32 = "NB2HI4DTHIXS65LQNRXWCZDGNFWGK4ZONFXQ====" nocase
    $site_19_encoded_base16 = "68747470733A2F2F75706C6F616466696C65732E696F" nocase
    $site_19_encoded_base85 = "XmoUNb2=|Cb#QENVPs}$Y-MvUX>R"
    $site_19_encoded_ascii85 = "BQS?8F#ks-F`;/8@:WtaCh7Z?Bl<"
    $site_19_encoded_uu = "aHR0cHM6Ly91cGxvYWRmaWxlcy5pbw==" nocase
    $site_19_encoded_rot47 = "9EEADi^^FA=@257:=6D]:@"
    $site_19_encoded_substitution = "kwwsv://xsordgilohv.lr"
    $site_19_encoded_caesar = "kwwsv=22xsordgilohv1lr"

    $site_20 = "https://0bin.net" nocase
    $site_20_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 37 48 CA CC D3 CB 4B 2D 01 00 D4 7E AA C4 10 00 00 00}
    $site_20_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 00 86 BA 21 00 00 03 99 80 00 01 C0 10 12 61 4C 00 20 00 22 00 0C 84 0D 03 43 66 10 54 9C 1B 04 39 F1 77 24 53 85 09 00 08 6B A2 10}
    $site_20_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 30 62 69 6E 2E 6E 65 74 00 33 82 48 18 D2 EC B5 24 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_20_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 37 48 CA CC D3 CB 4B 2D 01 00 30 CD 05 AA}
    $site_20_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 37 48 CA CC D3 CB 4B 2D 01 00 30 CD 05 AA}
    $site_20_encoded_lz4 = {04 22 4D 18 68 40 10 00 00 00 00 00 00 00 65 10 00 00 80 68 74 74 70 73 3A 2F 2F 30 62 69 6E 2E 6E 65 74 00 00 00 00}
    $site_20_encoded_zstd = {28 B5 2F FD 20 10 81 00 00 68 74 74 70 73 3A 2F 2F 30 62 69 6E 2E 6E 65 74}
    $site_20_encoded_snappy = {10 3C 68 74 74 70 73 3A 2F 2F 30 62 69 6E 2E 6E 65 74}
    $site_20_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 AE 58 51 C0 26 02 03 0B 90 00 04 90 00 B4 83 02 D4 7E AA C4 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 EC 4C 09 0A 68 74 74 70 73 3A 2F 2F 30 62 69 6E 2E 6E 65 74 1D 77 56 51 03 05 04 00}
    $site_20_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 37 48 CA CC D3 CB 4B 2D 01 00 D4 7E AA C4 10 00 00 00}
    $site_20_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 00 86 BA 21 00 00 03 99 80 00 01 C0 10 12 61 4C 00 20 00 22 00 0C 84 0D 03 43 66 10 54 9C 1B 04 39 F1 77 24 53 85 09 00 08 6B A2 10}
    $site_20_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 30 62 69 6E 2E 6E 65 74 00 33 82 48 18 D2 EC B5 24 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_20_encoded_base64 = "aHR0cHM6Ly8wYmluLm5ldA==" nocase
    $site_20_encoded_hex = "68747470733a2f2f3062696e2e6e6574" nocase
    $site_20_encoded_rot13 = "uggcf://0ova.arg"
    $site_20_encoded_base32 = "NB2HI4DTHIXS6MDCNFXC43TFOQ======" nocase
    $site_20_encoded_base16 = "68747470733A2F2F3062696E2E6E6574" nocase
    $site_20_encoded_base85 = "XmoUNb2=|CFk)$LE^cLX"
    $site_20_encoded_ascii85 = "BQS?8F#ks-0Oea6/oG6B"
    $site_20_encoded_uu = "aHR0cHM6Ly8wYmluLm5ldA==" nocase
    $site_20_encoded_rot5 = "https://5bin.net"
    $site_20_encoded_rot18 = "https://2bin.net"
    $site_20_encoded_rot47 = "9EEADi^^_3:?]?6E"
    $site_20_encoded_substitution = "kwwsv://0elq.qhw"
    $site_20_encoded_caesar = "kwwsv=223elq1qhw"

    $site_21 = "https://firefox.send" nocase
    $site_21_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB 2C 4A 4D CB AF D0 2B 4E CD 4B 01 00 3A 8B 53 A4 14 00 00 00}
    $site_21_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 83 81 EB 53 00 00 04 99 80 00 01 80 10 07 61 DC 40 20 00 22 99 A2 34 36 50 A6 00 01 00 7A 5C 55 71 D9 5A B0 57 C5 DC 91 4E 14 24 20 E0 7A D4 C0}
    $site_21_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 66 69 72 65 66 6F 78 2E 73 65 6E 64 00 28 6B 5A 64 9D 47 60 1A 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_21_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB 2C 4A 4D CB AF D0 2B 4E CD 4B 01 00 4F 69 07 97}
    $site_21_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CB 2C 4A 4D CB AF D0 2B 4E CD 4B 01 00 4F 69 07 97}
    $site_21_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 66 69 72 65 66 6F 78 2E 73 65 6E 64 00 00 00 00}
    $site_21_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 66 69 72 65 66 6F 78 2E 73 65 6E 64}
    $site_21_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 66 69 72 65 66 6F 78 2E 73 65 6E 64}
    $site_21_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 AE 18 1E 08 26 02 03 0B 94 00 04 94 00 B4 83 02 3A 8B 53 A4 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 BA 60 83 0A 68 74 74 70 73 3A 2F 2F 66 69 72 65 66 6F 78 2E 73 65 6E 64 1D 77 56 51 03 05 04 00}
    $site_21_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CB 2C 4A 4D CB AF D0 2B 4E CD 4B 01 00 3A 8B 53 A4 14 00 00 00}
    $site_21_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 83 81 EB 53 00 00 04 99 80 00 01 80 10 07 61 DC 40 20 00 22 99 A2 34 36 50 A6 00 01 00 7A 5C 55 71 D9 5A B0 57 C5 DC 91 4E 14 24 20 E0 7A D4 C0}
    $site_21_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 66 69 72 65 66 6F 78 2E 73 65 6E 64 00 28 6B 5A 64 9D 47 60 1A 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_21_encoded_base64 = "aHR0cHM6Ly9maXJlZm94LnNlbmQ=" nocase
    $site_21_encoded_hex = "68747470733a2f2f66697265666f782e73656e64" nocase
    $site_21_encoded_rot13 = "uggcf://sversbk.fraq"
    $site_21_encoded_base32 = "NB2HI4DTHIXS6ZTJOJSWM33YFZZWK3TE" nocase
    $site_21_encoded_base16 = "68747470733A2F2F66697265666F782E73656E64" nocase
    $site_21_encoded_base85 = "XmoUNb2=|CW@&O|W^Z^db7gL1"
    $site_21_encoded_ascii85 = "BQS?8F#ks-Anc9sAoDoHF(K6\""
    $site_21_encoded_uu = "aHR0cHM6Ly9maXJlZm94LnNlbmQ=" nocase
    $site_21_encoded_rot47 = "9EEADi^^7:C67@I]D6?5"
    $site_21_encoded_substitution = "kwwsv://iluhira.vhqg"
    $site_21_encoded_caesar = "kwwsv=22iluhir{1vhqg"

    $site_22 = "https://paste.ee" nocase
    $site_22_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 D5 4B 4D 05 00 74 7A FD 02 10 00 00 00}
    $site_22_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 10 9A 86 71 00 00 04 19 80 00 01 80 10 22 40 4C 00 20 00 22 06 4C 42 0C 98 82 03 71 2A E0 5A 13 C5 DC 91 4E 14 24 04 26 A1 9C 40}
    $site_22_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 2E 65 65 00 12 E2 78 A8 55 6F B4 64 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_22_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 D5 4B 4D 05 00 33 2D 05 E1}
    $site_22_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 D5 4B 4D 05 00 33 2D 05 E1}
    $site_22_encoded_lz4 = {04 22 4D 18 68 40 10 00 00 00 00 00 00 00 65 10 00 00 80 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 2E 65 65 00 00 00 00}
    $site_22_encoded_zstd = {28 B5 2F FD 20 10 81 00 00 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 2E 65 65}
    $site_22_encoded_snappy = {10 3C 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 2E 65 65}
    $site_22_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 F7 52 1B 30 26 02 03 0B 90 00 04 90 00 B4 83 02 74 7A FD 02 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 86 74 FD 0A 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 2E 65 65 1D 77 56 51 03 05 04 00}
    $site_22_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 D5 4B 4D 05 00 74 7A FD 02 10 00 00 00}
    $site_22_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 10 9A 86 71 00 00 04 19 80 00 01 80 10 22 40 4C 00 20 00 22 06 4C 42 0C 98 82 03 71 2A E0 5A 13 C5 DC 91 4E 14 24 04 26 A1 9C 40}
    $site_22_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 2E 65 65 00 12 E2 78 A8 55 6F B4 64 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_22_encoded_base64 = "aHR0cHM6Ly9wYXN0ZS5lZQ==" nocase
    $site_22_encoded_hex = "68747470733a2f2f70617374652e6565" nocase
    $site_22_encoded_rot13 = "uggcf://cnfgr.rr"
    $site_22_encoded_base32 = "NB2HI4DTHIXS64DBON2GKLTFMU======" nocase
    $site_22_encoded_base16 = "68747470733A2F2F70617374652E6565" nocase
    $site_22_encoded_base85 = "XmoUNb2=|CaA9+FWiDl9"
    $site_22_encoded_ascii85 = "BQS?8F#ks-E+*g0AM.P*"
    $site_22_encoded_uu = "aHR0cHM6Ly9wYXN0ZS5lZQ==" nocase
    $site_22_encoded_rot47 = "9EEADi^^A2DE6]66"
    $site_22_encoded_substitution = "kwwsv://sdvwh.hh"
    $site_22_encoded_caesar = "kwwsv=22sdvwh1hh"

    $site_23 = "https://pastebin.com" nocase
    $site_23_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 13 D2 C0 8B 14 00 00 00}
    $site_23_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 9C EA C9 4A 00 00 04 19 80 00 01 80 10 3A 63 CC 00 20 00 22 87 A9 91 B5 1E 50 A6 00 00 80 95 4B 45 B4 66 97 43 F8 BB 92 29 C2 84 84 E7 56 4A 50}
    $site_23_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 00 45 8E 5E 89 FE EC 36 4D 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_23_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 4F 8E 07 8F}
    $site_23_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 4F 8E 07 8F}
    $site_23_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 00 00 00 00}
    $site_23_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D}
    $site_23_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D}
    $site_23_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 DA 2C D1 4E 26 02 03 0B 94 00 04 94 00 B4 83 02 13 D2 C0 8B 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 6C 7E 3A 0B 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_23_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 48 2C 2E 49 4D CA CC D3 4B CE CF 05 00 13 D2 C0 8B 14 00 00 00}
    $site_23_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 9C EA C9 4A 00 00 04 19 80 00 01 80 10 3A 63 CC 00 20 00 22 87 A9 91 B5 1E 50 A6 00 00 80 95 4B 45 B4 66 97 43 F8 BB 92 29 C2 84 84 E7 56 4A 50}
    $site_23_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 70 61 73 74 65 62 69 6E 2E 63 6F 6D 00 45 8E 5E 89 FE EC 36 4D 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_23_encoded_base64 = "aHR0cHM6Ly9wYXN0ZWJpbi5jb20=" nocase
    $site_23_encoded_hex = "68747470733a2f2f706173746562696e2e636f6d" nocase
    $site_23_encoded_rot13 = "uggcf://cnfgrova.pbz"
    $site_23_encoded_base32 = "NB2HI4DTHIXS64DBON2GKYTJNYXGG33N" nocase
    $site_23_encoded_base16 = "68747470733A2F2F706173746562696E2E636F6D" nocase
    $site_23_encoded_base85 = "XmoUNb2=|CaA9+FWnyV=E@N+P"
    $site_23_encoded_ascii85 = "BQS?8F#ks-E+*g0AR]@k/n8g:"
    $site_23_encoded_uu = "aHR0cHM6Ly9wYXN0ZWJpbi5jb20=" nocase
    $site_23_encoded_rot47 = "9EEADi^^A2DE63:?]4@>"
    $site_23_encoded_substitution = "kwwsv://sdvwhelq.frp"
    $site_23_encoded_caesar = "kwwsv=22sdvwhelq1frp"

    $site_24 = "https://mega.nz" nocase
    $site_24_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF 4D 4D 4F D4 CB AB 02 00 A6 07 02 F1 0F 00 00 00}
    $site_24_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 8C 94 9B 4D 00 00 03 99 80 00 01 80 10 22 C3 4C 10 20 00 31 00 D0 01 03 42 7A 9A 7A 80 0D C3 C5 65 28 F2 F8 BB 92 29 C2 84 84 64 A4 DA 68}
    $site_24_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 6D 65 67 61 2E 6E 7A 00 00 92 FB 47 92 C9 4D E7 6D 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_24_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 CF 4D 4D 4F D4 CB AB 02 00 2C B7 05 7C}
    $site_24_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 CF 4D 4D 4F D4 CB AB 02 00 2C B7 05 7C}
    $site_24_encoded_lz4 = {04 22 4D 18 68 40 0F 00 00 00 00 00 00 00 16 0F 00 00 80 68 74 74 70 73 3A 2F 2F 6D 65 67 61 2E 6E 7A 00 00 00 00}
    $site_24_encoded_zstd = {28 B5 2F FD 20 0F 79 00 00 68 74 74 70 73 3A 2F 2F 6D 65 67 61 2E 6E 7A}
    $site_24_encoded_snappy = {0F 38 68 74 74 70 73 3A 2F 2F 6D 65 67 61 2E 6E 7A}
    $site_24_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 21 77 E5 34 26 02 03 0B 8F 00 04 8F 00 B4 83 02 A6 07 02 F1 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 3A 92 B4 0B 68 74 74 70 73 3A 2F 2F 6D 65 67 61 2E 6E 7A 1D 77 56 51 03 05 04 00}
    $site_24_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF 4D 4D 4F D4 CB AB 02 00 A6 07 02 F1 0F 00 00 00}
    $site_24_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 8C 94 9B 4D 00 00 03 99 80 00 01 80 10 22 C3 4C 10 20 00 31 00 D0 01 03 42 7A 9A 7A 80 0D C3 C5 65 28 F2 F8 BB 92 29 C2 84 84 64 A4 DA 68}
    $site_24_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 6D 65 67 61 2E 6E 7A 00 00 92 FB 47 92 C9 4D E7 6D 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_24_encoded_base64 = "aHR0cHM6Ly9tZWdhLm56" nocase
    $site_24_encoded_hex = "68747470733a2f2f6d6567612e6e7a" nocase
    $site_24_encoded_rot13 = "uggcf://zrtn.am"
    $site_24_encoded_base32 = "NB2HI4DTHIXS63LFM5QS43T2" nocase
    $site_24_encoded_base16 = "68747470733A2F2F6D6567612E6E7A" nocase
    $site_24_encoded_base85 = "XmoUNb2=|CZDnU+E^c}"
    $site_24_encoded_ascii85 = "BQS?8F#ks-D.R?g/oGt"
    $site_24_encoded_uu = "aHR0cHM6Ly9tZWdhLm56" nocase
    $site_24_encoded_rot47 = "9EEADi^^>682]?K"
    $site_24_encoded_substitution = "kwwsv://phjd.qc"
    $site_24_encoded_caesar = "kwwsv=22phjd1q}"

    $site_25 = "https://temp.sh" nocase
    $site_25_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 49 CD 2D D0 2B CE 00 00 B4 EB 84 AD 0F 00 00 00}
    $site_25_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 E6 B5 D8 54 00 00 03 19 80 00 01 80 10 02 42 4C 00 20 00 31 06 4C 41 03 43 D2 72 43 A0 78 31 77 8B B9 22 9C 28 48 73 5A EC 2A 00}
    $site_25_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 74 65 6D 70 2E 73 68 00 00 09 19 FC F6 1A 64 5A C0 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_25_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 49 CD 2D D0 2B CE 00 00 2D 3A 05 8B}
    $site_25_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 49 CD 2D D0 2B CE 00 00 2D 3A 05 8B}
    $site_25_encoded_lz4 = {04 22 4D 18 68 40 0F 00 00 00 00 00 00 00 16 0F 00 00 80 68 74 74 70 73 3A 2F 2F 74 65 6D 70 2E 73 68 00 00 00 00}
    $site_25_encoded_zstd = {28 B5 2F FD 20 0F 79 00 00 68 74 74 70 73 3A 2F 2F 74 65 6D 70 2E 73 68}
    $site_25_encoded_snappy = {0F 38 68 74 74 70 73 3A 2F 2F 74 65 6D 70 2E 73 68}
    $site_25_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 3B FD CF E5 26 02 03 0B 8F 00 04 8F 00 B4 83 02 B4 EB 84 AD 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 1F 9C F1 0B 68 74 74 70 73 3A 2F 2F 74 65 6D 70 2E 73 68 1D 77 56 51 03 05 04 00}
    $site_25_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 49 CD 2D D0 2B CE 00 00 B4 EB 84 AD 0F 00 00 00}
    $site_25_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 E6 B5 D8 54 00 00 03 19 80 00 01 80 10 02 42 4C 00 20 00 31 06 4C 41 03 43 D2 72 43 A0 78 31 77 8B B9 22 9C 28 48 73 5A EC 2A 00}
    $site_25_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0E 68 74 74 70 73 3A 2F 2F 74 65 6D 70 2E 73 68 00 00 09 19 FC F6 1A 64 5A C0 00 01 27 0F DF 1A FC 6A 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_25_encoded_base64 = "aHR0cHM6Ly90ZW1wLnNo" nocase
    $site_25_encoded_hex = "68747470733a2f2f74656d702e7368" nocase
    $site_25_encoded_rot13 = "uggcf://grzc.fu"
    $site_25_encoded_base32 = "NB2HI4DTHIXS65DFNVYC443I" nocase
    $site_25_encoded_base16 = "68747470733A2F2F74656D702E7368" nocase
    $site_25_encoded_base85 = "XmoUNb2=|CbY*RDE^}x"
    $site_25_encoded_ascii85 = "BQS?8F#ks-FCf<./ot\\"
    $site_25_encoded_uu = "aHR0cHM6Ly90ZW1wLnNo" nocase
    $site_25_encoded_rot47 = "9EEADi^^E6>A]D9"
    $site_25_encoded_substitution = "kwwsv://whps.vk"
    $site_25_encoded_caesar = "kwwsv=22whps1vk"

    $site_26 = "https://anonfile.com" nocase
    $site_26_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 D5 4B CE CF 05 00 74 DD 6C 20 14 00 00 00}
    $site_26_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 34 44 9D 72 00 00 04 19 80 00 01 80 10 2B 67 CC 00 20 00 22 9A 62 0C D4 DA 14 C0 01 34 75 5A 46 80 20 7F 12 36 4A 1B 17 72 45 38 50 90 34 44 9D 72}
    $site_26_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 2E 63 6F 6D 00 6E DD F8 8B C6 A5 27 8C 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_26_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 D5 4B CE CF 05 00 4F 29 07 85}
    $site_26_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 D5 4B CE CF 05 00 4F 29 07 85}
    $site_26_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 2E 63 6F 6D 00 00 00 00}
    $site_26_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 2E 63 6F 6D}
    $site_26_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 2E 63 6F 6D}
    $site_26_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 33 8E 00 18 26 02 03 0B 94 00 04 94 00 B4 83 02 74 DD 6C 20 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 ED AF 6B 0C 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_26_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 D5 4B CE CF 05 00 74 DD 6C 20 14 00 00 00}
    $site_26_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 34 44 9D 72 00 00 04 19 80 00 01 80 10 2B 67 CC 00 20 00 22 9A 62 0C D4 DA 14 C0 01 34 75 5A 46 80 20 7F 12 36 4A 1B 17 72 45 38 50 90 34 44 9D 72}
    $site_26_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 2E 63 6F 6D 00 6E DD F8 8B C6 A5 27 8C 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_26_encoded_base64 = "aHR0cHM6Ly9hbm9uZmlsZS5jb20=" nocase
    $site_26_encoded_hex = "68747470733a2f2f616e6f6e66696c652e636f6d" nocase
    $site_26_encoded_rot13 = "uggcf://nabasvyr.pbz"
    $site_26_encoded_base32 = "NB2HI4DTHIXS6YLON5XGM2LMMUXGG33N" nocase
    $site_26_encoded_base16 = "68747470733A2F2F616E6F6E66696C652E636F6D" nocase
    $site_26_encoded_base85 = "XmoUNb2=|CVQz13W@&6?E@N+P"
    $site_26_encoded_ascii85 = "BQS?8F#ks-@;^\"$Anc'm/n8g:"
    $site_26_encoded_uu = "aHR0cHM6Ly9hbm9uZmlsZS5jb20=" nocase
    $site_26_encoded_rot47 = "9EEADi^^2?@?7:=6]4@>"
    $site_26_encoded_substitution = "kwwsv://dqrqiloh.frp"
    $site_26_encoded_caesar = "kwwsv=22dqrqiloh1frp"

    $site_27 = "https://share.dmca.gripe" nocase
    $site_27_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F CE 48 2C 4A D5 4B C9 4D 4E D4 4B 2F CA 2C 48 05 00 ED 80 B3 0B 18 00 00 00}
    $site_27_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 16 59 F0 03 00 00 06 99 80 00 01 80 10 2E E2 5C 00 20 00 22 83 D1 1A 69 FA 90 A6 00 01 D2 43 C4 F0 32 FD 52 51 50 2F 7C 5D C9 14 E1 42 40 59 67 C0 0C}
    $site_27_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 17 68 74 74 70 73 3A 2F 2F 73 68 61 72 65 2E 64 6D 63 61 2E 67 72 69 70 65 00 D0 E2 16 79 C3 6A F6 8B 00 01 30 18 8E 1B AC EC 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_27_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F CE 48 2C 4A D5 4B C9 4D 4E D4 4B 2F CA 2C 48 05 00 6F 14 08 E7}
    $site_27_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F CE 48 2C 4A D5 4B C9 4D 4E D4 4B 2F CA 2C 48 05 00 6F 14 08 E7}
    $site_27_encoded_lz4 = {04 22 4D 18 68 40 18 00 00 00 00 00 00 00 4F 18 00 00 80 68 74 74 70 73 3A 2F 2F 73 68 61 72 65 2E 64 6D 63 61 2E 67 72 69 70 65 00 00 00 00}
    $site_27_encoded_zstd = {28 B5 2F FD 20 18 C1 00 00 68 74 74 70 73 3A 2F 2F 73 68 61 72 65 2E 64 6D 63 61 2E 67 72 69 70 65}
    $site_27_encoded_snappy = {18 5C 68 74 74 70 73 3A 2F 2F 73 68 61 72 65 2E 64 6D 63 61 2E 67 72 69 70 65}
    $site_27_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 12 D3 09 2A 26 02 03 0B 98 00 04 98 00 B4 83 02 ED 80 B3 0B 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 B9 C3 E5 0C 68 74 74 70 73 3A 2F 2F 73 68 61 72 65 2E 64 6D 63 61 2E 67 72 69 70 65 1D 77 56 51 03 05 04 00}
    $site_27_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F CE 48 2C 4A D5 4B C9 4D 4E D4 4B 2F CA 2C 48 05 00 ED 80 B3 0B 18 00 00 00}
    $site_27_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 16 59 F0 03 00 00 06 99 80 00 01 80 10 2E E2 5C 00 20 00 22 83 D1 1A 69 FA 90 A6 00 01 D2 43 C4 F0 32 FD 52 51 50 2F 7C 5D C9 14 E1 42 40 59 67 C0 0C}
    $site_27_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 17 68 74 74 70 73 3A 2F 2F 73 68 61 72 65 2E 64 6D 63 61 2E 67 72 69 70 65 00 D0 E2 16 79 C3 6A F6 8B 00 01 30 18 8E 1B AC EC 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_27_encoded_base64 = "aHR0cHM6Ly9zaGFyZS5kbWNhLmdyaXBl" nocase
    $site_27_encoded_hex = "68747470733a2f2f73686172652e646d63612e6772697065" nocase
    $site_27_encoded_rot13 = "uggcf://funer.qzpn.tevcr"
    $site_27_encoded_base32 = "NB2HI4DTHIXS643IMFZGKLTENVRWCLTHOJUXAZI=" nocase
    $site_27_encoded_base16 = "68747470733A2F2F73686172652E646D63612E6772697065" nocase
    $site_27_encoded_base85 = "XmoUNb2=|Cb7*05WiDiGV_`05a%pg7"
    $site_27_encoded_ascii85 = "BQS?8F#ks-F(f!&AM.M1@pq!&EbTK("
    $site_27_encoded_uu = "aHR0cHM6Ly9zaGFyZS5kbWNhLmdyaXBl" nocase
    $site_27_encoded_rot47 = "9EEADi^^D92C6]5>42]8C:A6"
    $site_27_encoded_substitution = "kwwsv://vkduh.gpfd.julsh"
    $site_27_encoded_caesar = "kwwsv=22vkduh1gpfd1julsh"

    $site_28 = "https://drive.google.com" nocase
    $site_28_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 29 CA 2C 4B D5 4B CF CF 4F CF 49 D5 4B CE CF 05 00 68 28 C3 46 18 00 00 00}
    $site_28_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 33 69 8D 43 00 00 05 99 80 00 01 80 10 0E E6 DD 00 20 00 22 23 35 00 7A 9B 50 A1 A6 98 00 B3 44 78 3E D1 06 7A 1B 8E 8A 79 5F 17 72 45 38 50 90 33 69 8D 43}
    $site_28_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 17 68 74 74 70 73 3A 2F 2F 64 72 69 76 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D 00 E1 FF 8F E8 25 3F 25 07 00 01 30 18 8E 1B AC EC 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_28_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 29 CA 2C 4B D5 4B CF CF 4F CF 49 D5 4B CE CF 05 00 70 66 08 FE}
    $site_28_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 29 CA 2C 4B D5 4B CF CF 4F CF 49 D5 4B CE CF 05 00 70 66 08 FE}
    $site_28_encoded_lz4 = {04 22 4D 18 68 40 18 00 00 00 00 00 00 00 4F 18 00 00 80 68 74 74 70 73 3A 2F 2F 64 72 69 76 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D 00 00 00 00}
    $site_28_encoded_zstd = {28 B5 2F FD 20 18 C1 00 00 68 74 74 70 73 3A 2F 2F 64 72 69 76 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D}
    $site_28_encoded_snappy = {18 5C 68 74 74 70 73 3A 2F 2F 64 72 69 76 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D}
    $site_28_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 B8 C5 56 00 26 02 03 0B 98 00 04 98 00 B4 83 02 68 28 C3 46 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 9F CD 22 0D 68 74 74 70 73 3A 2F 2F 64 72 69 76 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_28_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 29 CA 2C 4B D5 4B CF CF 4F CF 49 D5 4B CE CF 05 00 68 28 C3 46 18 00 00 00}
    $site_28_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 33 69 8D 43 00 00 05 99 80 00 01 80 10 0E E6 DD 00 20 00 22 23 35 00 7A 9B 50 A1 A6 98 00 B3 44 78 3E D1 06 7A 1B 8E 8A 79 5F 17 72 45 38 50 90 33 69 8D 43}
    $site_28_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 17 68 74 74 70 73 3A 2F 2F 64 72 69 76 65 2E 67 6F 6F 67 6C 65 2E 63 6F 6D 00 E1 FF 8F E8 25 3F 25 07 00 01 30 18 8E 1B AC EC 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_28_encoded_base64 = "aHR0cHM6Ly9kcml2ZS5nb29nbGUuY29t" nocase
    $site_28_encoded_hex = "68747470733a2f2f64726976652e676f6f676c652e636f6d" nocase
    $site_28_encoded_rot13 = "uggcf://qevir.tbbtyr.pbz"
    $site_28_encoded_base32 = "NB2HI4DTHIXS6ZDSNF3GKLTHN5XWO3DFFZRW63I=" nocase
    $site_28_encoded_base16 = "68747470733A2F2F64726976652E676F6F676C652E636F6D" nocase
    $site_28_encoded_base85 = "XmoUNb2=|CWO8YCWiDrLZ)a>}E@N+P"
    $site_28_encoded_ascii85 = "BQS?8F#ks-A9)C-AM.V6DeElt/n8g:"
    $site_28_encoded_uu = "aHR0cHM6Ly9kcml2ZS5nb29nbGUuY29t" nocase
    $site_28_encoded_rot47 = "9EEADi^^5C:G6]8@@8=6]4@>"
    $site_28_encoded_substitution = "kwwsv://gulyh.jrrjoh.frp"
    $site_28_encoded_caesar = "kwwsv=22gulyh1jrrjoh1frp"

    $site_29 = "https://dfile.space" nocase
    $site_29_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 49 CB CC 49 D5 2B 2E 48 4C 4E 05 00 2B 81 5C 62 13 00 00 00}
    $site_29_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 A5 91 E3 D5 00 00 05 19 80 00 01 80 10 2F 64 4C 00 20 00 22 87 A9 93 13 F5 21 00 00 1D 20 74 44 C5 13 74 6E FE 2E E4 8A 70 A1 21 4B 23 C7 AA}
    $site_29_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 64 66 69 6C 65 2E 73 70 61 63 65 00 00 A7 31 65 42 A3 2F 9A 06 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_29_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 49 CB CC 49 D5 2B 2E 48 4C 4E 05 00 46 A4 07 0A}
    $site_29_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 49 CB CC 49 D5 2B 2E 48 4C 4E 05 00 46 A4 07 0A}
    $site_29_encoded_lz4 = {04 22 4D 18 68 40 13 00 00 00 00 00 00 00 FA 13 00 00 80 68 74 74 70 73 3A 2F 2F 64 66 69 6C 65 2E 73 70 61 63 65 00 00 00 00}
    $site_29_encoded_zstd = {28 B5 2F FD 20 13 99 00 00 68 74 74 70 73 3A 2F 2F 64 66 69 6C 65 2E 73 70 61 63 65}
    $site_29_encoded_snappy = {13 48 68 74 74 70 73 3A 2F 2F 64 66 69 6C 65 2E 73 70 61 63 65}
    $site_29_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 7D E8 10 F2 26 02 03 0B 93 00 04 93 00 B4 83 02 2B 81 5C 62 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 6D E1 9C 0D 68 74 74 70 73 3A 2F 2F 64 66 69 6C 65 2E 73 70 61 63 65 1D 77 56 51 03 05 04 00}
    $site_29_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 49 CB CC 49 D5 2B 2E 48 4C 4E 05 00 2B 81 5C 62 13 00 00 00}
    $site_29_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 A5 91 E3 D5 00 00 05 19 80 00 01 80 10 2F 64 4C 00 20 00 22 87 A9 93 13 F5 21 00 00 1D 20 74 44 C5 13 74 6E FE 2E E4 8A 70 A1 21 4B 23 C7 AA}
    $site_29_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 12 68 74 74 70 73 3A 2F 2F 64 66 69 6C 65 2E 73 70 61 63 65 00 00 A7 31 65 42 A3 2F 9A 06 00 01 2B 13 9C 09 48 D2 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_29_encoded_base64 = "aHR0cHM6Ly9kZmlsZS5zcGFjZQ==" nocase
    $site_29_encoded_hex = "68747470733a2f2f6466696c652e7370616365" nocase
    $site_29_encoded_rot13 = "uggcf://qsvyr.fcnpr"
    $site_29_encoded_base32 = "NB2HI4DTHIXS6ZDGNFWGKLTTOBQWGZI=" nocase
    $site_29_encoded_base16 = "68747470733A2F2F6466696C652E7370616365" nocase
    $site_29_encoded_base85 = "XmoUNb2=|CWM*k>WiE4YVPj<"
    $site_29_encoded_ascii85 = "BQS?8F#ks-A7fOlAM/%C@:Nj"
    $site_29_encoded_uu = "aHR0cHM6Ly9kZmlsZS5zcGFjZQ==" nocase
    $site_29_encoded_rot47 = "9EEADi^^57:=6]DA246"
    $site_29_encoded_substitution = "kwwsv://giloh.vsdfh"
    $site_29_encoded_caesar = "kwwsv=22giloh1vsdfh"

    $site_30 = "https://easyupload.io" nocase
    $site_30_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 4D 2C AE 2C 2D C8 C9 4F 4C D1 CB CC 07 00 C6 D1 96 8E 15 00 00 00}
    $site_30_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 4F 01 F6 A9 00 00 04 19 80 00 01 80 10 26 64 CE 20 20 00 22 87 94 7A 87 A9 EA 0A 60 00 08 0F 89 10 9B 72 1D 5E 7B BF 17 72 45 38 50 90 4F 01 F6 A9}
    $site_30_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 65 61 73 79 75 70 6C 6F 61 64 2E 69 6F 00 00 00 00 1F CD 27 26 6E 45 06 D5 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_30_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 4D 2C AE 2C 2D C8 C9 4F 4C D1 CB CC 07 00 58 82 08 09}
    $site_30_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 4D 2C AE 2C 2D C8 C9 4F 4C D1 CB CC 07 00 58 82 08 09}
    $site_30_encoded_lz4 = {04 22 4D 18 68 40 15 00 00 00 00 00 00 00 36 15 00 00 80 68 74 74 70 73 3A 2F 2F 65 61 73 79 75 70 6C 6F 61 64 2E 69 6F 00 00 00 00}
    $site_30_encoded_zstd = {28 B5 2F FD 20 15 A9 00 00 68 74 74 70 73 3A 2F 2F 65 61 73 79 75 70 6C 6F 61 64 2E 69 6F}
    $site_30_encoded_snappy = {15 50 68 74 74 70 73 3A 2F 2F 65 61 73 79 75 70 6C 6F 61 64 2E 69 6F}
    $site_30_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 B5 28 30 F8 26 02 03 0B 95 00 04 95 00 B4 83 02 C6 D1 96 8E 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 52 EB D9 0D 68 74 74 70 73 3A 2F 2F 65 61 73 79 75 70 6C 6F 61 64 2E 69 6F 1D 77 56 51 03 05 04 00}
    $site_30_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 4D 2C AE 2C 2D C8 C9 4F 4C D1 CB CC 07 00 C6 D1 96 8E 15 00 00 00}
    $site_30_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 4F 01 F6 A9 00 00 04 19 80 00 01 80 10 26 64 CE 20 20 00 22 87 94 7A 87 A9 EA 0A 60 00 08 0F 89 10 9B 72 1D 5E 7B BF 17 72 45 38 50 90 4F 01 F6 A9}
    $site_30_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 65 61 73 79 75 70 6C 6F 61 64 2E 69 6F 00 00 00 00 1F CD 27 26 6E 45 06 D5 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_30_encoded_base64 = "aHR0cHM6Ly9lYXN5dXBsb2FkLmlv" nocase
    $site_30_encoded_hex = "68747470733a2f2f6561737975706c6f61642e696f" nocase
    $site_30_encoded_rot13 = "uggcf://rnflhcybnq.vb"
    $site_30_encoded_base32 = "NB2HI4DTHIXS6ZLBON4XK4DMN5QWILTJN4======" nocase
    $site_30_encoded_base16 = "68747470733A2F2F6561737975706C6F61642E696F" nocase
    $site_30_encoded_base85 = "XmoUNb2=|CWnpu9b#QENVPr08Zv"
    $site_30_encoded_ascii85 = "BQS?8F#ks-ARTY*F`;/8@:V!)DZ"
    $site_30_encoded_uu = "aHR0cHM6Ly9lYXN5dXBsb2FkLmlv" nocase
    $site_30_encoded_rot47 = "9EEADi^^62DJFA=@25]:@"
    $site_30_encoded_substitution = "kwwsv://hdvbxsordg.lr"
    $site_30_encoded_caesar = "kwwsv=22hdv|xsordg1lr"

    $site_31 = "https://rentry.co" nocase
    $site_31_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4A CD 2B 29 AA D4 4B CE 07 00 47 B9 5F 5A 11 00 00 00}
    $site_31_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 47 69 86 6F 00 00 03 19 80 00 01 80 10 0A 41 DC 20 20 00 22 9A 69 A6 D4 CF 50 80 68 00 77 BE DD 24 4B 0C 0B 05 DC 91 4E 14 24 11 DA 61 9B C0}
    $site_31_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 10 68 74 74 70 73 3A 2F 2F 72 65 6E 74 72 79 2E 63 6F 00 00 00 00 13 B8 EA 2C 2C 21 73 D7 00 01 29 11 32 0A 70 0E 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_31_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4A CD 2B 29 AA D4 4B CE 07 00 3A 50 06 70}
    $site_31_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4A CD 2B 29 AA D4 4B CE 07 00 3A 50 06 70}
    $site_31_encoded_lz4 = {04 22 4D 18 68 40 11 00 00 00 00 00 00 00 E8 11 00 00 80 68 74 74 70 73 3A 2F 2F 72 65 6E 74 72 79 2E 63 6F 00 00 00 00}
    $site_31_encoded_zstd = {28 B5 2F FD 20 11 89 00 00 68 74 74 70 73 3A 2F 2F 72 65 6E 74 72 79 2E 63 6F}
    $site_31_encoded_snappy = {11 40 68 74 74 70 73 3A 2F 2F 72 65 6E 74 72 79 2E 63 6F}
    $site_31_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 40 3D 07 27 26 02 03 0B 91 00 04 91 00 B4 83 02 47 B9 5F 5A 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 1F FF 53 0E 68 74 74 70 73 3A 2F 2F 72 65 6E 74 72 79 2E 63 6F 1D 77 56 51 03 05 04 00}
    $site_31_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4A CD 2B 29 AA D4 4B CE 07 00 47 B9 5F 5A 11 00 00 00}
    $site_31_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 47 69 86 6F 00 00 03 19 80 00 01 80 10 0A 41 DC 20 20 00 22 9A 69 A6 D4 CF 50 80 68 00 77 BE DD 24 4B 0C 0B 05 DC 91 4E 14 24 11 DA 61 9B C0}
    $site_31_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 10 68 74 74 70 73 3A 2F 2F 72 65 6E 74 72 79 2E 63 6F 00 00 00 00 13 B8 EA 2C 2C 21 73 D7 00 01 29 11 32 0A 70 0E 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_31_encoded_base64 = "aHR0cHM6Ly9yZW50cnkuY28=" nocase
    $site_31_encoded_hex = "68747470733a2f2f72656e7472792e636f" nocase
    $site_31_encoded_rot13 = "uggcf://eragel.pb"
    $site_31_encoded_base32 = "NB2HI4DTHIXS64TFNZ2HE6JOMNXQ====" nocase
    $site_31_encoded_base16 = "68747470733A2F2F72656E7472792E636F" nocase
    $site_31_encoded_base85 = "XmoUNb2=|Ca%FCGa(OOeZv"
    $site_31_encoded_ascii85 = "BQS?8F#ks-Eb0-1Ed99IDZ"
    $site_31_encoded_uu = "aHR0cHM6Ly9yZW50cnkuY28=" nocase
    $site_31_encoded_rot47 = "9EEADi^^C6?ECJ]4@"
    $site_31_encoded_substitution = "kwwsv://uhqwub.fr"
    $site_31_encoded_caesar = "kwwsv=22uhqwu|1fr"

    $site_32 = "https://wetransfer.com" nocase
    $site_32_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4F 2D 29 4A CC 2B 4E 4B 2D D2 4B CE CF 05 00 67 84 B6 80 16 00 00 00}
    $site_32_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 A3 00 E9 CC 00 00 04 99 80 00 01 80 10 2B 43 DC 80 20 00 22 87 A2 03 27 EA 85 30 00 4D 21 29 4D A1 BB 3B E1 16 0B A3 DF 17 72 45 38 50 90 A3 00 E9 CC}
    $site_32_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 15 68 74 74 70 73 3A 2F 2F 77 65 74 72 61 6E 73 66 65 72 2E 63 6F 6D 00 00 00 AE 00 7C 91 F3 A8 BB 67 00 01 2E 16 56 09 55 DF 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_32_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4F 2D 29 4A CC 2B 4E 4B 2D D2 4B CE CF 05 00 61 52 08 7A}
    $site_32_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4F 2D 29 4A CC 2B 4E 4B 2D D2 4B CE CF 05 00 61 52 08 7A}
    $site_32_encoded_lz4 = {04 22 4D 18 68 40 16 00 00 00 00 00 00 00 E8 16 00 00 80 68 74 74 70 73 3A 2F 2F 77 65 74 72 61 6E 73 66 65 72 2E 63 6F 6D 00 00 00 00}
    $site_32_encoded_zstd = {28 B5 2F FD 20 16 B1 00 00 68 74 74 70 73 3A 2F 2F 77 65 74 72 61 6E 73 66 65 72 2E 63 6F 6D}
    $site_32_encoded_snappy = {16 54 68 74 74 70 73 3A 2F 2F 77 65 74 72 61 6E 73 66 65 72 2E 63 6F 6D}
    $site_32_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 69 8B 82 5C 26 02 03 0B 96 00 04 96 00 B4 83 02 67 84 B6 80 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 EC 12 CE 0E 68 74 74 70 73 3A 2F 2F 77 65 74 72 61 6E 73 66 65 72 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_32_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4F 2D 29 4A CC 2B 4E 4B 2D D2 4B CE CF 05 00 67 84 B6 80 16 00 00 00}
    $site_32_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 A3 00 E9 CC 00 00 04 99 80 00 01 80 10 2B 43 DC 80 20 00 22 87 A2 03 27 EA 85 30 00 4D 21 29 4D A1 BB 3B E1 16 0B A3 DF 17 72 45 38 50 90 A3 00 E9 CC}
    $site_32_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 15 68 74 74 70 73 3A 2F 2F 77 65 74 72 61 6E 73 66 65 72 2E 63 6F 6D 00 00 00 AE 00 7C 91 F3 A8 BB 67 00 01 2E 16 56 09 55 DF 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_32_encoded_base64 = "aHR0cHM6Ly93ZXRyYW5zZmVyLmNvbQ==" nocase
    $site_32_encoded_hex = "68747470733a2f2f77657472616e736665722e636f6d" nocase
    $site_32_encoded_rot13 = "uggcf://jrgenafsre.pbz"
    $site_32_encoded_base32 = "NB2HI4DTHIXS653FORZGC3TTMZSXELTDN5WQ====" nocase
    $site_32_encoded_base16 = "68747470733A2F2F77657472616E736665722E636F6D" nocase
    $site_32_encoded_base85 = "XmoUNb2=|CcV%>PVQzC~WpXZKZ*2"
    $site_32_encoded_ascii85 = "BQS?8F#ks-G@bl:@;^-uATBD5Df#"
    $site_32_encoded_uu = "aHR0cHM6Ly93ZXRyYW5zZmVyLmNvbQ==" nocase
    $site_32_encoded_rot47 = "9EEADi^^H6EC2?D76C]4@>"
    $site_32_encoded_substitution = "kwwsv://zhwudqvihu.frp"
    $site_32_encoded_caesar = "kwwsv=22zhwudqvihu1frp"

    $site_33 = "https://ufile.io" nocase
    $site_33_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4D CB CC 49 D5 CB CC 07 00 32 11 07 31 10 00 00 00}
    $site_33_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 B2 94 37 C4 00 00 03 19 80 00 01 80 10 03 64 CE 00 20 00 22 9A 7A 23 D3 4D 42 01 A0 00 02 2D 12 B4 DC 35 F1 77 24 53 85 09 0B 29 43 7C 40}
    $site_33_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 75 66 69 6C 65 2E 69 6F 00 F4 07 76 3B 83 7C 01 8C 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_33_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4D CB CC 49 D5 CB CC 07 00 33 26 05 E7}
    $site_33_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 2F 4D CB CC 49 D5 CB CC 07 00 33 26 05 E7}
    $site_33_encoded_lz4 = {04 22 4D 18 68 40 10 00 00 00 00 00 00 00 65 10 00 00 80 68 74 74 70 73 3A 2F 2F 75 66 69 6C 65 2E 69 6F 00 00 00 00}
    $site_33_encoded_zstd = {28 B5 2F FD 20 10 81 00 00 68 74 74 70 73 3A 2F 2F 75 66 69 6C 65 2E 69 6F}
    $site_33_encoded_snappy = {10 3C 68 74 74 70 73 3A 2F 2F 75 66 69 6C 65 2E 69 6F}
    $site_33_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 57 5D 47 69 26 02 03 0B 90 00 04 90 00 B4 83 02 32 11 07 31 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 D2 1C 0B 0F 68 74 74 70 73 3A 2F 2F 75 66 69 6C 65 2E 69 6F 1D 77 56 51 03 05 04 00}
    $site_33_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 2F 4D CB CC 49 D5 CB CC 07 00 32 11 07 31 10 00 00 00}
    $site_33_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 B2 94 37 C4 00 00 03 19 80 00 01 80 10 03 64 CE 00 20 00 22 9A 7A 23 D3 4D 42 01 A0 00 02 2D 12 B4 DC 35 F1 77 24 53 85 09 0B 29 43 7C 40}
    $site_33_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 0F 68 74 74 70 73 3A 2F 2F 75 66 69 6C 65 2E 69 6F 00 F4 07 76 3B 83 7C 01 8C 00 01 28 10 E5 0B 6C 60 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_33_encoded_base64 = "aHR0cHM6Ly91ZmlsZS5pbw==" nocase
    $site_33_encoded_hex = "68747470733a2f2f7566696c652e696f" nocase
    $site_33_encoded_rot13 = "uggcf://hsvyr.vb"
    $site_33_encoded_base32 = "NB2HI4DTHIXS65LGNFWGKLTJN4======" nocase
    $site_33_encoded_base16 = "68747470733A2F2F7566696C652E696F" nocase
    $site_33_encoded_base85 = "XmoUNb2=|Cb!KU7WiDxN"
    $site_33_encoded_ascii85 = "BQS?8F#ks-F_5?(AM.\\8"
    $site_33_encoded_uu = "aHR0cHM6Ly91ZmlsZS5pbw==" nocase
    $site_33_encoded_rot47 = "9EEADi^^F7:=6]:@"
    $site_33_encoded_substitution = "kwwsv://xiloh.lr"
    $site_33_encoded_caesar = "kwwsv=22xiloh1lr"

    $site_34 = "https://ghostbin.com" nocase
    $site_34_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CF C8 2F 2E 49 CA CC D3 4B CE CF 05 00 FF D5 EF 61 14 00 00 00}
    $site_34_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 CC 70 8B 20 00 00 04 19 80 00 01 80 10 18 E3 CC 00 20 00 31 00 00 0A 1E A6 98 64 48 0A D8 41 84 8A 9B 62 3D 82 EE 48 A7 0A 12 19 8E 11 64 00}
    $site_34_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 67 68 6F 73 74 62 69 6E 2E 63 6F 6D 00 2F AC DD 34 23 86 9A A7 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_34_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CF C8 2F 2E 49 CA CC D3 4B CE CF 05 00 4F B6 07 97}
    $site_34_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CF C8 2F 2E 49 CA CC D3 4B CE CF 05 00 4F B6 07 97}
    $site_34_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 67 68 6F 73 74 62 69 6E 2E 63 6F 6D 00 00 00 00}
    $site_34_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 67 68 6F 73 74 62 69 6E 2E 63 6F 6D}
    $site_34_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 67 68 6F 73 74 62 69 6E 2E 63 6F 6D}
    $site_34_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 2A E0 F2 5B 26 02 03 0B 94 00 04 94 00 B4 83 02 FF D5 EF 61 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 A0 30 85 0F 68 74 74 70 73 3A 2F 2F 67 68 6F 73 74 62 69 6E 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_34_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CF C8 2F 2E 49 CA CC D3 4B CE CF 05 00 FF D5 EF 61 14 00 00 00}
    $site_34_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 CC 70 8B 20 00 00 04 19 80 00 01 80 10 18 E3 CC 00 20 00 31 00 00 0A 1E A6 98 64 48 0A D8 41 84 8A 9B 62 3D 82 EE 48 A7 0A 12 19 8E 11 64 00}
    $site_34_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 67 68 6F 73 74 62 69 6E 2E 63 6F 6D 00 2F AC DD 34 23 86 9A A7 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_34_encoded_base64 = "aHR0cHM6Ly9naG9zdGJpbi5jb20=" nocase
    $site_34_encoded_hex = "68747470733a2f2f67686f737462696e2e636f6d" nocase
    $site_34_encoded_rot13 = "uggcf://tubfgova.pbz"
    $site_34_encoded_base32 = "NB2HI4DTHIXS6Z3IN5ZXIYTJNYXGG33N" nocase
    $site_34_encoded_base16 = "68747470733A2F2F67686F737462696E2E636F6D" nocase
    $site_34_encoded_base85 = "XmoUNb2=|CXJ~J8bYf|4E@N+P"
    $site_34_encoded_ascii85 = "BQS?8F#ks-B4u4)FCJs%/n8g:"
    $site_34_encoded_uu = "aHR0cHM6Ly9naG9zdGJpbi5jb20=" nocase
    $site_34_encoded_rot47 = "9EEADi^^89@DE3:?]4@>"
    $site_34_encoded_substitution = "kwwsv://jkrvwelq.frp"
    $site_34_encoded_caesar = "kwwsv=22jkrvwelq1frp"

    $site_35 = "https://api.ipify.org" nocase
    $site_35_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 2C C8 D4 CB 2C C8 4C AB D4 CB 2F 4A 07 00 F2 14 4C 83 15 00 00 00}
    $site_35_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 0B FA 0C 57 00 00 04 19 80 00 01 80 10 21 E0 DC 20 20 00 22 20 F4 86 8F 6A 84 00 00 D8 93 BA 74 E3 91 52 13 80 F8 BB 92 29 C2 84 80 5F D0 62 B8}
    $site_35_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 61 70 69 2E 69 70 69 66 79 2E 6F 72 67 00 00 00 00 23 A9 60 05 3D 80 3F F4 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_35_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 2C C8 D4 CB 2C C8 4C AB D4 CB 2F 4A 07 00 55 5C 07 CB}
    $site_35_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 2C C8 D4 CB 2C C8 4C AB D4 CB 2F 4A 07 00 55 5C 07 CB}
    $site_35_encoded_lz4 = {04 22 4D 18 68 40 15 00 00 00 00 00 00 00 36 15 00 00 80 68 74 74 70 73 3A 2F 2F 61 70 69 2E 69 70 69 66 79 2E 6F 72 67 00 00 00 00}
    $site_35_encoded_zstd = {28 B5 2F FD 20 15 A9 00 00 68 74 74 70 73 3A 2F 2F 61 70 69 2E 69 70 69 66 79 2E 6F 72 67}
    $site_35_encoded_snappy = {15 50 68 74 74 70 73 3A 2F 2F 61 70 69 2E 69 70 69 66 79 2E 6F 72 67}
    $site_35_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 FB AA D9 98 26 02 03 0B 95 00 04 95 00 B4 83 02 F2 14 4C 83 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 85 3A C2 0F 68 74 74 70 73 3A 2F 2F 61 70 69 2E 69 70 69 66 79 2E 6F 72 67 1D 77 56 51 03 05 04 00}
    $site_35_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 2C C8 D4 CB 2C C8 4C AB D4 CB 2F 4A 07 00 F2 14 4C 83 15 00 00 00}
    $site_35_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 0B FA 0C 57 00 00 04 19 80 00 01 80 10 21 E0 DC 20 20 00 22 20 F4 86 8F 6A 84 00 00 D8 93 BA 74 E3 91 52 13 80 F8 BB 92 29 C2 84 80 5F D0 62 B8}
    $site_35_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 61 70 69 2E 69 70 69 66 79 2E 6F 72 67 00 00 00 00 23 A9 60 05 3D 80 3F F4 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_35_encoded_base64 = "aHR0cHM6Ly9hcGkuaXBpZnkub3Jn" nocase
    $site_35_encoded_hex = "68747470733a2f2f6170692e69706966792e6f7267" nocase
    $site_35_encoded_rot13 = "uggcf://ncv.vcvsl.bet"
    $site_35_encoded_base32 = "NB2HI4DTHIXS6YLQNEXGS4DJMZ4S433SM4======" nocase
    $site_35_encoded_base16 = "68747470733A2F2F6170692E69706966792E6F7267" nocase
    $site_35_encoded_base85 = "XmoUNb2=|CVQ^_KX>e&~c`k2qX8"
    $site_35_encoded_ascii85 = "BQS?8F#ks-@;op5BlIcuGqO#UB)"
    $site_35_encoded_uu = "aHR0cHM6Ly9hcGkuaXBpZnkub3Jn" nocase
    $site_35_encoded_rot47 = "9EEADi^^2A:]:A:7J]@C8"
    $site_35_encoded_substitution = "kwwsv://dsl.lslib.ruj"
    $site_35_encoded_caesar = "kwwsv=22dsl1lsli|1ruj"

    $site_36 = "https://dropmefiles.com" nocase
    $site_36_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 29 CA 2F C8 4D 4D CB CC 49 2D D6 4B CE CF 05 00 45 4F D5 0F 17 00 00 00}
    $site_36_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 A2 2C 48 2A 00 00 04 99 80 00 01 80 10 0F 66 DC 00 20 00 22 8F 28 1A 7A 08 53 00 04 D2 49 04 25 D0 CA 21 48 A9 6D 9A F8 BB 92 29 C2 84 85 11 62 41 50}
    $site_36_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 16 68 74 74 70 73 3A 2F 2F 64 72 6F 70 6D 65 66 69 6C 65 73 2E 63 6F 6D 00 00 EF 0E 93 BB 2F 2B CE 11 00 01 2F 17 81 08 49 B1 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_36_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F 29 CA 2F C8 4D 4D CB CC 49 2D D6 4B CE CF 05 00 69 8E 08 D3}
    $site_36_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F 29 CA 2F C8 4D 4D CB CC 49 2D D6 4B CE CF 05 00 69 8E 08 D3}
    $site_36_encoded_lz4 = {04 22 4D 18 68 40 17 00 00 00 00 00 00 00 32 17 00 00 80 68 74 74 70 73 3A 2F 2F 64 72 6F 70 6D 65 66 69 6C 65 73 2E 63 6F 6D 00 00 00 00}
    $site_36_encoded_zstd = {28 B5 2F FD 20 17 B9 00 00 68 74 74 70 73 3A 2F 2F 64 72 6F 70 6D 65 66 69 6C 65 73 2E 63 6F 6D}
    $site_36_encoded_snappy = {17 58 68 74 74 70 73 3A 2F 2F 64 72 6F 70 6D 65 66 69 6C 65 73 2E 63 6F 6D}
    $site_36_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 B7 5B 9A E6 26 02 03 0B 97 00 04 97 00 B4 83 02 45 4F D5 0F 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 52 4E 3C 10 68 74 74 70 73 3A 2F 2F 64 72 6F 70 6D 65 66 69 6C 65 73 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_36_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F 29 CA 2F C8 4D 4D CB CC 49 2D D6 4B CE CF 05 00 45 4F D5 0F 17 00 00 00}
    $site_36_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 A2 2C 48 2A 00 00 04 99 80 00 01 80 10 0F 66 DC 00 20 00 22 8F 28 1A 7A 08 53 00 04 D2 49 04 25 D0 CA 21 48 A9 6D 9A F8 BB 92 29 C2 84 85 11 62 41 50}
    $site_36_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 16 68 74 74 70 73 3A 2F 2F 64 72 6F 70 6D 65 66 69 6C 65 73 2E 63 6F 6D 00 00 EF 0E 93 BB 2F 2B CE 11 00 01 2F 17 81 08 49 B1 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_36_encoded_base64 = "aHR0cHM6Ly9kcm9wbWVmaWxlcy5jb20=" nocase
    $site_36_encoded_hex = "68747470733a2f2f64726f706d6566696c65732e636f6d" nocase
    $site_36_encoded_rot13 = "uggcf://qebczrsvyrf.pbz"
    $site_36_encoded_base32 = "NB2HI4DTHIXS6ZDSN5YG2ZLGNFWGK4ZOMNXW2===" nocase
    $site_36_encoded_base16 = "68747470733A2F2F64726F706D6566696C65732E636F6D" nocase
    $site_36_encoded_base85 = "XmoUNb2=|CWO8qCZDnR@Y-MvUV{dH"
    $site_36_encoded_ascii85 = "BQS?8F#ks-A9)U-D.R<nCh7Z?@rH2"
    $site_36_encoded_uu = "aHR0cHM6Ly9kcm9wbWVmaWxlcy5jb20=" nocase
    $site_36_encoded_rot47 = "9EEADi^^5C@A>67:=6D]4@>"
    $site_36_encoded_substitution = "kwwsv://gursphilohv.frp"
    $site_36_encoded_caesar = "kwwsv=22gursphilohv1frp"

    $site_37 = "https://anonfiles.com" nocase
    $site_37_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 2D D6 4B CE CF 05 00 EC 3B 98 24 15 00 00 00}
    $site_37_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 23 08 11 DF 00 00 04 19 80 00 01 80 10 2B 67 CC 00 20 00 22 8D A8 0F 53 D2 7A 85 30 00 4D 3C 04 58 14 8A 9A 1E E5 CB 87 F1 77 24 53 85 09 02 30 81 1D F0}
    $site_37_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D 00 00 00 00 D3 D2 BF 98 4F 23 F4 03 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_37_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 2D D6 4B CE CF 05 00 57 80 07 F8}
    $site_37_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 2D D6 4B CE CF 05 00 57 80 07 F8}
    $site_37_encoded_lz4 = {04 22 4D 18 68 40 15 00 00 00 00 00 00 00 36 15 00 00 80 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D 00 00 00 00}
    $site_37_encoded_zstd = {28 B5 2F FD 20 15 A9 00 00 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D}
    $site_37_encoded_snappy = {15 50 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D}
    $site_37_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 74 AC E8 09 26 02 03 0B 95 00 04 95 00 B4 83 02 EC 3B 98 24 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 3A 58 79 10 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D 1D 77 56 51 03 05 04 00}
    $site_37_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 4F CC CB CF 4B CB CC 49 2D D6 4B CE CF 05 00 EC 3B 98 24 15 00 00 00}
    $site_37_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 23 08 11 DF 00 00 04 19 80 00 01 80 10 2B 67 CC 00 20 00 22 8D A8 0F 53 D2 7A 85 30 00 4D 3C 04 58 14 8A 9A 1E E5 CB 87 F1 77 24 53 85 09 02 30 81 1D F0}
    $site_37_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 14 68 74 74 70 73 3A 2F 2F 61 6E 6F 6E 66 69 6C 65 73 2E 63 6F 6D 00 00 00 00 D3 D2 BF 98 4F 23 F4 03 00 01 2D 15 2F 0B 71 6D 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_37_encoded_base64 = "aHR0cHM6Ly9hbm9uZmlsZXMuY29t" nocase
    $site_37_encoded_hex = "68747470733a2f2f616e6f6e66696c65732e636f6d" nocase
    $site_37_encoded_rot13 = "uggcf://nabasvyrf.pbz"
    $site_37_encoded_base32 = "NB2HI4DTHIXS6YLON5XGM2LMMVZS4Y3PNU======" nocase
    $site_37_encoded_base16 = "68747470733A2F2F616E6F6E66696C65732E636F6D" nocase
    $site_37_encoded_base85 = "XmoUNb2=|CVQz13W@&6?b1q|VZ2"
    $site_37_encoded_ascii85 = "BQS?8F#ks-@;^\"$Anc'mF\"Us@D#"
    $site_37_encoded_uu = "aHR0cHM6Ly9hbm9uZmlsZXMuY29t" nocase
    $site_37_encoded_rot47 = "9EEADi^^2?@?7:=6D]4@>"
    $site_37_encoded_substitution = "kwwsv://dqrqilohv.frp"
    $site_37_encoded_caesar = "kwwsv=22dqrqilohv1frp"

    $site_38 = "https://justpaste.it" nocase
    $site_38_encoded_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF 2A 2D 2E 29 48 2C 2E 49 D5 CB 2C 01 00 22 25 08 F8 14 00 00 00}
    $site_38_encoded_bz2 = {42 5A 68 39 31 41 59 26 53 59 63 CA 78 1B 00 00 03 19 80 00 01 80 10 22 70 4E 00 20 00 22 06 80 D0 40 D0 34 20 0D D2 95 0E 82 FA 8B 49 EF 17 72 45 38 50 90 63 CA 78 1B}
    $site_38_encoded_lzma = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 6A 75 73 74 70 61 73 74 65 2E 69 74 00 12 1D AB 5D 64 BF 21 A5 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_38_encoded_deflate = {78 9C CB 28 29 29 28 B6 D2 D7 CF 2A 2D 2E 29 48 2C 2E 49 D5 CB 2C 01 00 51 05 07 BA}
    $site_38_encoded_zlib = {78 9C CB 28 29 29 28 B6 D2 D7 CF 2A 2D 2E 29 48 2C 2E 49 D5 CB 2C 01 00 51 05 07 BA}
    $site_38_encoded_lz4 = {04 22 4D 18 68 40 14 00 00 00 00 00 00 00 A3 14 00 00 80 68 74 74 70 73 3A 2F 2F 6A 75 73 74 70 61 73 74 65 2E 69 74 00 00 00 00}
    $site_38_encoded_zstd = {28 B5 2F FD 20 14 A1 00 00 68 74 74 70 73 3A 2F 2F 6A 75 73 74 70 61 73 74 65 2E 69 74}
    $site_38_encoded_snappy = {14 4C 68 74 74 70 73 3A 2F 2F 6A 75 73 74 70 61 73 74 65 2E 69 74}
    $site_38_encoded_rar = {52 61 72 21 1A 07 01 00 33 92 B5 E5 0A 01 05 06 00 05 01 01 80 80 00 F4 74 39 A5 26 02 03 0B 94 00 04 94 00 B4 83 02 22 25 08 F8 80 00 01 08 74 65 6D 70 2E 74 78 74 0A 03 13 40 10 98 66 05 6C F3 10 68 74 74 70 73 3A 2F 2F 6A 75 73 74 70 61 73 74 65 2E 69 74 1D 77 56 51 03 05 04 00}
    $site_38_encoded_tar_gz = {1F 8B 08 00 40 10 98 66 02 FF CB 28 29 29 28 B6 D2 D7 CF 2A 2D 2E 29 48 2C 2E 49 D5 CB 2C 01 00 22 25 08 F8 14 00 00 00}
    $site_38_encoded_tar_bz2 = {42 5A 68 39 31 41 59 26 53 59 63 CA 78 1B 00 00 03 19 80 00 01 80 10 22 70 4E 00 20 00 22 06 80 D0 40 D0 34 20 0D D2 95 0E 82 FA 8B 49 EF 17 72 45 38 50 90 63 CA 78 1B}
    $site_38_encoded_tar_xz = {FD 37 7A 58 5A 00 00 04 E6 D6 B4 46 02 00 21 01 16 00 00 00 74 2F E5 A3 01 00 13 68 74 74 70 73 3A 2F 2F 6A 75 73 74 70 61 73 74 65 2E 69 74 00 12 1D AB 5D 64 BF 21 A5 00 01 2C 14 F8 0A 6D 03 1F B6 F3 7D 01 00 00 00 00 04 59 5A}
    $site_38_encoded_base64 = "aHR0cHM6Ly9qdXN0cGFzdGUuaXQ=" nocase
    $site_38_encoded_hex = "68747470733a2f2f6a75737470617374652e6974" nocase
    $site_38_encoded_rot13 = "uggcf://whfgcnfgr.vg"
    $site_38_encoded_base32 = "NB2HI4DTHIXS62TVON2HAYLTORSS42LU" nocase
    $site_38_encoded_base16 = "68747470733A2F2F6A75737470617374652E6974" nocase
    $site_38_encoded_base85 = "XmoUNb2=|CYISpTaA9+FWiDxS"
    $site_38_encoded_ascii85 = "BQS?8F#ks-C3=T>E+*g0AM.\\="
    $site_38_encoded_uu = "aHR0cHM6Ly9qdXN0cGFzdGUuaXQ=" nocase
    $site_38_encoded_rot47 = "9EEADi^^;FDEA2DE6]:E"
    $site_38_encoded_substitution = "kwwsv://mxvwsdvwh.lw"
    $site_38_encoded_caesar = "kwwsv=22mxvwsdvwh1lw"

  condition:
    any of them
}
