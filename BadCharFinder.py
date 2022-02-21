import argparse
import os
import sys
import re

def type_byteList(bList):
    """
    byte type which checks the byte format.
    """
    if not re.match("^[0-9a-fa-f]+$", bList) or len(bList)%2 != 0:
        print(f"Missing byte list should use the following format: \"FF0A\"")
        sys.exit(1)
    return bList

def type_byte(b):
    """
    byte type which checks the byte format.
    """
    if not re.match("^[0-9a-fa-f][0-9a-fa-f]$", b):
        print(f"Byte should use the following format: \"FF\"")
        sys.exit(1)
    return b

def type_file(filename):
    """
    file type which checks if the file exists.
    """
    if not os.path.isfile(filename):
        print(f"File {filename} doesn't exist!")
        sys.exit(1)
    return filename

def displayFileFormat():
    print("""file format should be a windbg dump, example:
    
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
0046e892  f3 f4 f5 f6 f7 f8 f9 fa-fb fc fd fe ff 0d ab ab  ................""")

def checkFileFormat(badbytesFile):
    for line in open(badbytesFile):
        strippedLine = line.replace("-", "").replace(" ", "")[:40]
        if len(strippedLine) > 1 and not re.match("^[0-9a-fa-f]{40}$", strippedLine):
            displayFileFormat()
            return False
    return True

def generateByteList(startByte, endByte, missingBytes):
    byteList = []
    missingByteList = [missingBytes[i:i+2] for i in range(0, len(missingBytes), 2)]
    for i in range(int(startByte, 16), int(endByte, 16)+1):
        save = True
        for b in missingByteList:
            if i == int(b, 16):
                save = False
                break
        if save:
            byteList.append(format(i, "02x"))
    return byteList

def compareBytes(b1, b2):
    return int(b1, 16) == int(b2, 16)

def findBadChars(badbytesFile, startByte, endByte, missingBytes):
    retList = []
    bCharList = generateByteList(startByte, endByte, missingBytes)
    bCharFileList = []
    foundStart = False
    for line in open(badbytesFile):
        strippedLine = line.replace("-", "").replace(" ", "")[8:40]
        byteList = [strippedLine[i:i+2] for i in range(0, len(strippedLine), 2)]
        bCharFileList += byteList

    curIndex = 0
    while not foundStart:
        if compareBytes(bCharFileList[curIndex], bCharList[0]):
            foundStart = True
        if curIndex > len(bCharFileList):
            print(f"Didn't find the startByte in the windbg dumpfile!")
            sys.exit(1)
        curIndex += 1

    nIndex = 1
    while nIndex < len(bCharList):
        if not compareBytes(bCharFileList[curIndex], bCharList[nIndex]):
            retList.append(bCharList[nIndex])
        curIndex += 1
        nIndex += 1
    return retList

def run(badbytesFile, startByte, endByte, missingBytes):
    if not checkFileFormat(badbytesFile):
        sys.exit(1)
    print("BadCharacters = b\"", end="")
    for badChar in findBadChars(badbytesFile, startByte, endByte, missingBytes):
        print(f"\\x{badChar}", end="")
    print("\"")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Script to quickly find the bad characters in a windbg dump.')
    parser.add_argument("-f", "--file", type=type_file, required=True,
                        help="Filename of the badbytes file.")
    parser.add_argument("-s", "--startbyte", type=type_byte, required=False,
                        help="The first byte to look for, default = 01.")
    parser.add_argument("-e", "--endbyte", type=type_byte, required=False,
                        help="The last byte to look for, default = ff.")
    parser.add_argument("-m", "--missing", type=type_byteList, required=False,
                        help="A list of missing bytes to skip over, example = 0a0nfe")

    args = parser.parse_args()

    if not args.startbyte:
        args.startbyte = "01"

    if not args.endbyte:
        args.endbyte = "ff"

    if not args.missing:
        args.missing = ""

    run(args.file, args.startbyte, args.endbyte, args.missing)
