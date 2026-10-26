"""
Create minimal valid Windows PE files for ClarusAV demo scanning.
"""
import os, struct, random, time

os.makedirs("samples", exist_ok=True)

def build_pe(size_hint: int, entropy_hint: float, timestamp: int) -> bytes:
    """Build a minimal but structurally valid PE binary."""
    rng = random.Random(timestamp)

    # DOS header (64 bytes), e_lfanew points to offset 64
    dos = b"MZ" + b"\x90" * 58 + struct.pack("<I", 64)

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,     # Machine: x86
        2,          # NumberOfSections
        timestamp,
        0, 0,
        0xE0,       # SizeOfOptionalHeader = 224
        0x0102,     # Characteristics
    )

    # Optional header (PE32 = 0x10B, total size = 224 bytes = 0xE0)
    opt = struct.pack("<H", 0x010B)   # Magic
    opt += bytes([14, 0])             # Linker ver
    opt += struct.pack(
        "<IIIIIIIIIHHHHHHIIIIHHIIIIII",
        size_hint,      # SizeOfCode
        0,              # SizeOfInitializedData
        0,              # SizeOfUninitializedData
        0x1000,         # AddressOfEntryPoint
        0x1000,         # BaseOfCode
        0x2000,         # BaseOfData
        0x400000,       # ImageBase
        0x1000,         # SectionAlignment
        0x200,          # FileAlignment
        6, 0,           # OS version
        0, 0,           # Image version
        4, 0,           # Subsystem version
        0,              # Win32VersionValue
        size_hint + 0x3000,  # SizeOfImage
        0x400,          # SizeOfHeaders
        0,              # CheckSum
        3,              # Subsystem (console)
        0x8140,         # DllCharacteristics
        0x100000, 0x1000,   # StackReserve/Commit
        0x100000, 0x1000,   # HeapReserve/Commit
        0,              # LoaderFlags
        16,             # NumberOfRvaAndSizes
    )
    # 16 data directory entries (zero) = 128 bytes
    opt += b"\x00" * (16 * 8)

    # Section data
    sec1_size = max(512, size_hint // 2)
    sec2_size = max(512, size_hint // 2)

    # Generate bytes with target entropy
    def make_section(sz: int, entropy: float) -> bytes:
        if entropy > 6.5:
            return bytes(rng.randint(0, 255) for _ in range(sz))
        elif entropy > 4.0:
            pool = bytes(range(32, 127))
            return bytes(rng.choice(pool) for _ in range(sz))
        else:
            chunk = b"\x90\x00\x48\x65\x6c\x6c\x6f"
            return (chunk * (sz // len(chunk) + 1))[:sz]

    raw1 = make_section(sec1_size, entropy_hint)
    raw2 = make_section(sec2_size, max(1.0, entropy_hint - 1.5))

    # Section headers (40 bytes each)
    hdr_offset = 64 + 4 + 20 + 0xE0          # dos + PE sig + coff + opt
    data_offset = 0x400                        # rounded up to file alignment

    sh1 = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        sec1_size, 0x1000, sec1_size, data_offset,
        0, 0, 0, 0, 0x60000020,
    )
    sh2 = struct.pack(
        "<8sIIIIIIHHI",
        b".data\x00\x00\x00",
        sec2_size, 0x2000, sec2_size, data_offset + sec1_size,
        0, 0, 0, 0, 0xC0000040,
    )

    header_blob = dos + pe_sig + coff + opt + sh1 + sh2
    header_blob = header_blob.ljust(0x400, b"\x00")   # pad to file alignment

    return header_blob + raw1 + raw2


# ── BENIGN: small, low entropy ────────────────────────────────────────────────
benign = build_pe(size_hint=18000, entropy_hint=3.1, timestamp=1_400_000_000)
with open("samples/benign_calc.exe", "wb") as f:
    f.write(benign)
print(f"[+] samples/benign_calc.exe      {len(benign):,} bytes  (benign profile)")

# ── MALWARE: large, high entropy ──────────────────────────────────────────────
malware = build_pe(size_hint=65000, entropy_hint=7.4, timestamp=int(time.time()))
with open("samples/malware_ransom.exe", "wb") as f:
    f.write(malware)
print(f"[+] samples/malware_ransom.exe   {len(malware):,} bytes  (malware profile)")

# ── SUSPICIOUS: mid-range ─────────────────────────────────────────────────────
mid = build_pe(size_hint=40000, entropy_hint=5.8, timestamp=int(time.time()) - 86400)
with open("samples/suspicious_mid.exe", "wb") as f:
    f.write(mid)
print(f"[+] samples/suspicious_mid.exe   {len(mid):,} bytes  (suspicious/mid profile)")

print("\nDone — sample PE files ready in ./samples/")
