import struct
import zlib

def create_png(width, height, color):
    def png_chunk(chunk_type, data):
        chunk_len = len(data)
        chunk_data = chunk_type + data
        crc = zlib.crc32(chunk_data) & 0xffffffff
        return struct.pack('>I', chunk_len) + chunk_data + struct.pack('>I', crc)
    
    signature = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    ihdr = png_chunk(b'IHDR', ihdr_data)
    
    raw_data = b''
    r, g, b = color
    for y in range(height):
        raw_data += b'\x00'
        for x in range(width):
            raw_data += bytes([r, g, b])
    
    compressed = zlib.compress(raw_data)
    idat = png_chunk(b'IDAT', compressed)
    iend = png_chunk(b'IEND', b'')
    
    return signature + ihdr + idat + iend

icon = create_png(48, 48, (98, 0, 238))

sizes = {
    'mipmap-mdpi': 48,
    'mipmap-hdpi': 72,
    'mipmap-xhdpi': 96,
    'mipmap-xxhdpi': 144,
    'mipmap-xxxhdpi': 192
}

import os
for folder, size in sizes.items():
    path = f'app/src/main/res/{folder}'
    os.makedirs(path, exist_ok=True)
    png = create_png(size, size, (98, 0, 238))
    with open(f'{path}/ic_launcher.png', 'wb') as f:
        f.write(png)
    print(f'Created {path}/ic_launcher.png ({size}x{size})')

print('Done!')
