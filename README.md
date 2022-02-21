# BadCharFinder
A simple script to parse debug output to find the bad characters, mainly created to speed up the process of finding bad characters during the OSED course.


## Example
```text
dev@: python3 ./BadCharFinder.py -f badbytesexample
BadCharacters = b"\x37\x68\xb5\xc5\xe8"
```

## Usage
```text
usage: BadCharFinder.py [-h] -f FILE [-s STARTBYTE] [-e ENDBYTE] [-m MISSING]

Script to quickly find the bad characters in a windbg dump.

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Filename of the badbytes file.
  -s STARTBYTE, --startbyte STARTBYTE
                        The first byte to look for, default = 01.
  -e ENDBYTE, --endbyte ENDBYTE
                        The last byte to look for, default = ff.
  -m MISSING, --missing MISSING
                        A list of missing bytes to skip over, example = 0a0nfe
```

## BadByteFile Example
    NOTE: The bytes 0x08 and 0x0a are missing in example, supply these through -m flag.
```text
0046e7a2  01 02 03 04 05 06 07 09-0b 0c 0d 0e 0f 10 11 12  ................
0046e7b2  13 14 15 16 17 18 19 1a-1b 1c 1d 1e 1f 20 21 b0  ............. !.
0046e7c2  23 24 25 26 27 28 29 2a-2b 2c 2d 2e 2f 30 31 32  #$%&'()*+,-./012
0046e7d2  33 34 35 36 37 38 39 3a-3b 3c 3d 3e 3f 40 41 42  3456789:;<=>?@AB
0046e7e2  43 44 45 46 47 48 49 4a-4b 4c 4d 4e 4f 50 51 52  CDEFGHIJKLMNOPQR
0046e7f2  53 54 55 56 57 58 59 5a-5b 5c 5d 5e 5f 60 61 62  STUVWXYZ[\]^_`ab
0046e802  63 64 65 66 67 68 69 6a-6b 6c 6d 6e 6f 70 71 72  cdefghijklmnopqr
0046e812  73 74 75 76 77 78 79 7a-7b 7c 7d 7e 7f 80 81 82  stuvwxyz{|}~....
0046e822  83 84 85 86 87 88 89 8a-8b 8c 8d 8e 8f 90 91 92  ................
0046e832  93 94 95 96 97 98 99 9a-9b 9c 9d 9e 9f a0 a1 a2  ................
0046e842  a3 a4 a5 a6 a7 a8 a9 aa-ab ac ad ae af b0 b1 b2  ................
0046e852  b3 b4 b5 b6 b7 b8 b9 ba-bb bc bd be bf c0 c1 c2  ................
0046e862  c3 c4 b0 c6 c7 c8 c9 ca-cb cc cd ce cf d0 d1 d2  ................
0046e872  d3 d4 d5 d6 d7 d8 d9 da-db dc dd de df e0 e1 e2  ................
0046e882  e3 e4 e5 e6 e7 b0 e9 ea-eb ec ed ee ef f0 f1 f2  ................
0046e892  f3 f4 f5 f6 f7 f8 f9 fa-fb fc fd fe ff 0d ab ab  ................
```