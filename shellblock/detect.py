"""In charge of detecting the magic numbers of a given file and comparing them 
against the file type they claim to be in their extension"""

# _magicNumbers = {
#     "jpeg":"ffd8ff",
#     "png": "89504e470d0a1a0a",
#     "php":"3c3f",
# }

_extensions = {
    "jpeg":["jpeg", "jpg"],
    "png":["png"],
    "gif":["gif"],
    "php":["php3","php4", "php4", "php5", "php7"],
    "pcap":["pcap"]
}

def FindMagic(filePath: str):
    '''Finds the magic numbers for the file in the given filepath'''
    susFile = open(filePath, "rb")
    susFile.seek(0)

    firstBytes = susFile.read(32)
    hexFirstBytes = firstBytes.hex()

    # print(f"jpeg magic: {_magicNumbers.get("jpeg")}")
    # print(f"first 32 bytes in hex: {hexFirstBytes}")
    for i in _magicNumbers.keys():
        #n for the index where it is found, -1 if it ain't found
        foundMagic = hexFirstBytes.find(_magicNumbers.get(i))
        # print(f"found magic hex for {_magicNumbers[i]}: {foundMagic}")


FindMagic("C:/Users/ikeum/Downloads/WhatsApp Image 2026-11-16 at 16.09.30.jpeg")