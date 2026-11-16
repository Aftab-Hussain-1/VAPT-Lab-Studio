/**
 * Minimal pure-TypeScript ZIP archive builder (Store method + IEEE 802.3 CRC32).
 * Enables instant offline client-side GitHub repository bundle downloads.
 */

export interface ZipEntryInput {
  path: string;
  content: string;
  executable?: boolean;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function writeUint16LE(view: DataView, offset: number, value: number) {
  view.setUint16(offset, value & 0xffff, true);
}

function writeUint32LE(view: DataView, offset: number, value: number) {
  view.setUint32(offset, value >>> 0, true);
}

export function buildZipBlob(entries: ZipEntryInput[]): Blob {
  const encoder = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;

  const now = new Date();
  const dosTime =
    ((now.getHours() & 0x1f) << 11) |
    ((now.getMinutes() & 0x3f) << 5) |
    ((now.getSeconds() >> 1) & 0x1f);
  const dosDate =
    (((Math.max(1980, now.getFullYear()) - 1980) & 0x7f) << 9) |
    (((now.getMonth() + 1) & 0x0f) << 5) |
    (now.getDate() & 0x1f);

  for (const entry of entries) {
    const cleanPath = entry.path.replace(/^\/+/, '');
    const nameBytes = encoder.encode(cleanPath);
    const dataBytes = encoder.encode(entry.content);
    const crc = crc32(dataBytes);

    // Local file header (30 bytes + filename)
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(localHeader.buffer);
    writeUint32LE(lv, 0, 0x04034b50); // Local file header signature
    writeUint16LE(lv, 4, 20); // Version needed
    writeUint16LE(lv, 6, 0x0800); // UTF-8 filename flag
    writeUint16LE(lv, 8, 0); // Compression method 0 (Store)
    writeUint16LE(lv, 10, dosTime);
    writeUint16LE(lv, 12, dosDate);
    writeUint32LE(lv, 14, crc);
    writeUint32LE(lv, 18, dataBytes.length);
    writeUint32LE(lv, 22, dataBytes.length);
    writeUint16LE(lv, 26, nameBytes.length);
    writeUint16LE(lv, 28, 0); // Extra field length
    localHeader.set(nameBytes, 30);

    localParts.push(localHeader, dataBytes);

    // Central directory header (46 bytes + filename)
    const centralHeader = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(centralHeader.buffer);
    writeUint32LE(cv, 0, 0x02014b50); // Central file header signature
    writeUint16LE(cv, 4, (3 << 8) | 20); // Made by Unix (3), version 2.0
    writeUint16LE(cv, 6, 20); // Version needed
    writeUint16LE(cv, 8, 0x0800); // UTF-8 flag
    writeUint16LE(cv, 10, 0); // Store
    writeUint16LE(cv, 12, dosTime);
    writeUint16LE(cv, 14, dosDate);
    writeUint32LE(cv, 16, crc);
    writeUint32LE(cv, 20, dataBytes.length);
    writeUint32LE(cv, 24, dataBytes.length);
    writeUint16LE(cv, 28, nameBytes.length);
    writeUint16LE(cv, 30, 0); // Extra length
    writeUint16LE(cv, 32, 0); // Comment length
    writeUint16LE(cv, 34, 0); // Disk number
    writeUint16LE(cv, 36, 0); // Internal attrs
    // External attrs: Unix permissions (-rwxr-xr-x = 0100755 or -rw-r--r-- = 0100644)
    const unixMode = entry.executable ? 0o100755 : 0o100644;
    writeUint32LE(cv, 38, unixMode << 16);
    writeUint32LE(cv, 42, offset); // Relative offset of local header
    centralHeader.set(nameBytes, 46);

    centralParts.push(centralHeader);
    offset += localHeader.length + dataBytes.length;
  }

  let centralSize = 0;
  for (const part of centralParts) {
    centralSize += part.length;
  }

  const endRecord = new Uint8Array(22);
  const ev = new DataView(endRecord.buffer);
  writeUint32LE(ev, 0, 0x06054b50); // End of central directory signature
  writeUint16LE(ev, 4, 0);
  writeUint16LE(ev, 6, 0);
  writeUint16LE(ev, 8, entries.length);
  writeUint16LE(ev, 10, entries.length);
  writeUint32LE(ev, 12, centralSize);
  writeUint32LE(ev, 16, offset);
  writeUint16LE(ev, 20, 0);

  const allParts = [...localParts, ...centralParts, endRecord];
  const totalBytes = allParts.reduce((acc, part) => acc + part.length, 0);
  const combined = new Uint8Array(totalBytes);
  let writeOffset = 0;
  for (const part of allParts) {
    combined.set(part, writeOffset);
    writeOffset += part.length;
  }

  return new Blob([combined.buffer], {
    type: 'application/zip',
  });
}
