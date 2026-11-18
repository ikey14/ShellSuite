"""In charge of detecting the magic numbers of a given file and comparing them 
against the file type they claim to be in their extension"""

from pathlib import Path

from shellblock.helpers.jsonLoader import load_json

data = load_json("info.json")
_magicNumbers = data["magicNumbers"]
_extensions = data["extensions"]

def FindMagic(filePath: str) -> tuple[str, str, bool]:
    '''Finds the magic numbers for the file in the given filepath'''
    susFile = open(filePath, "rb")
    matchedType = ""
    matchedTypeExts = ""
    magExtMatch = True
    fileExt = Path(filePath).suffix.lstrip(".").lower()
    print(f"File Extension: {fileExt}")

    for ext in _magicNumbers:
        for magic in ext["magic"]:
            susFile.seek(ext["offset"])
            #Because magic is char representation of hex, 1 hex = 8 bytes = 2 chars, so len must be half
            magLen = len(magic) // 2

            if susFile.read(magLen).hex() == magic:
                # print(f"Match found, {ext['type']} magic present")
                matchedType = ext["type"]
                matchedTypeExts = _extensions[matchedType]

                if fileExt not in matchedTypeExts:
                    magExtMatch = False

                susFile.close()
                return matchedType, fileExt, magExtMatch


# magType, fileExt, trueFile = FindMagic("C:/Users/ikeum/Downloads/WhatsApp Image 2026-11-16 at 16.09.30.jpeg")
# print(f"magicType: {magType}, fileExtension: {fileExt}, magic corroborates extension: {trueFile}")
# magType, fileExt, trueFile = FindMagic("C:/Users/ikeum/Downloads/BLE_Packet.png")
# print(f"magicType: {magType}, fileExtension: {fileExt}, magic corroborates extension: {trueFile}")