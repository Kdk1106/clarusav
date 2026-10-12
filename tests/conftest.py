"""Pytest configuration and synthetic PE generator fixtures."""

import hashlib
import struct

import pefile
import pytest

from clarusav.config import ClarusConfig, load_config
from clarusav.features.entropy import calculate_entropy


def build_synthetic_pe(
    sections: list[tuple[str, bytes]],
    imports: dict[str, list[str]] | None = None,
    timestamp: int = 1515456000,  # 2018-01-09T00:00:00Z
) -> bytes:
    """Construct a structurally valid minimal Windows PE32 binary with arbitrary sections and imports.

    Args:
        sections: List of tuples (section_name, raw_data_bytes).
        imports: Mapping of DLL name -> list of imported function names.
        timestamp: PE COFF header TimeDateStamp.

    Returns:
        Raw bytes of a valid PE binary parsable by pefile.
    """
    imports = imports or {}
    sec_count = len(sections) + (1 if imports else 0)

    # DOS Header
    dos_header = bytearray(64)
    dos_header[:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew = 64

    pe_sig = b"PE\x00\x00"

    # COFF Header (20 bytes)
    coff = struct.pack("<HHIIIHH", 0x14C, sec_count, timestamp, 0, 0, 224, 0x102)

    # Layout calculation
    file_align = 0x200
    sec_align = 0x1000
    hdr_size = file_align

    # Build import data section if imports specified
    import_sec_data = bytearray()
    if imports:
        # Build import directory table
        # We will place imports in an .idata or .rdata section
        descriptor_size = 20
        num_dlls = len(imports)
        descriptors_size = (num_dlls + 1) * descriptor_size

        # Layout after descriptors:
        # For each DLL: ILT table, IAT table, DLL name, Hint/Name items
        current_offset = descriptors_size
        dll_blocks: list[dict] = []

        for dll_name, funcs in imports.items():
            num_funcs = len(funcs)
            ilt_offset = current_offset
            current_offset += (num_funcs + 1) * 4  # 32-bit RVAs, null terminated
            iat_offset = current_offset
            current_offset += (num_funcs + 1) * 4

            name_bytes = dll_name.encode("ascii") + b"\x00"
            name_offset = current_offset
            current_offset += len(name_bytes)

            func_offsets = []
            for func in funcs:
                func_bytes = struct.pack("<H", 0) + func.encode("ascii") + b"\x00"
                func_offsets.append(current_offset)
                current_offset += len(func_bytes)

            dll_blocks.append(
                {
                    "dll_name": dll_name,
                    "ilt_offset": ilt_offset,
                    "iat_offset": iat_offset,
                    "name_offset": name_offset,
                    "func_offsets": func_offsets,
                    "name_bytes": name_bytes,
                    "funcs": funcs,
                }
            )

        # Total size of import section padded to file_align
        total_import_size = ((current_offset + file_align - 1) // file_align) * file_align
        import_sec_data = bytearray(total_import_size)

        # Base RVA for imports section will be determined by its section RVA
        # We will compute RVAs once sections are placed

    # Compute section placement
    current_file_offset = hdr_size
    current_rva = sec_align

    sec_headers = bytearray()
    all_sec_raw = bytearray()

    import_rva = 0
    import_size = 0

    for sec_name, raw_data in sections:
        raw_size = ((len(raw_data) + file_align - 1) // file_align) * file_align
        padded_raw = raw_data.ljust(raw_size, b"\x00") if raw_size > 0 else b""
        virt_size = len(raw_data) if len(raw_data) > 0 else file_align

        name_padded = sec_name.encode("ascii")[:8].ljust(8, b"\x00")
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            name_padded,
            virt_size,
            current_rva,
            raw_size,
            current_file_offset if raw_size > 0 else 0,
            0,
            0,
            0,
            0,
            0x60000020,
        )
        sec_headers.extend(sec_hdr)
        all_sec_raw.extend(padded_raw)

        current_file_offset += raw_size
        current_rva += ((virt_size + sec_align - 1) // sec_align) * sec_align

    if imports:
        # Now place import section
        import_rva = current_rva
        import_size = len(import_sec_data)
        import_raw_size = import_size
        import_file_offset = current_file_offset

        # Fill import_sec_data with absolute RVAs based on import_rva
        for i, block in enumerate(dll_blocks):
            desc_offset = i * 20
            struct.pack_into(
                "<IIIII",
                import_sec_data,
                desc_offset,
                import_rva + block["ilt_offset"],
                0,
                0,
                import_rva + block["name_offset"],
                import_rva + block["iat_offset"],
            )

            # Pack ILT and IAT
            for j, f_offset in enumerate(block["func_offsets"]):
                struct.pack_into(
                    "<I", import_sec_data, block["ilt_offset"] + j * 4, import_rva + f_offset
                )
                struct.pack_into(
                    "<I", import_sec_data, block["iat_offset"] + j * 4, import_rva + f_offset
                )
            struct.pack_into(
                "<I", import_sec_data, block["ilt_offset"] + len(block["func_offsets"]) * 4, 0
            )
            struct.pack_into(
                "<I", import_sec_data, block["iat_offset"] + len(block["func_offsets"]) * 4, 0
            )

            # DLL name
            import_sec_data[
                block["name_offset"] : block["name_offset"] + len(block["name_bytes"])
            ] = block["name_bytes"]

            # Functions
            for j, func in enumerate(block["funcs"]):
                f_offset = block["func_offsets"][j]
                struct.pack_into("<H", import_sec_data, f_offset, j + 1)
                f_name_bytes = func.encode("ascii") + b"\x00"
                import_sec_data[f_offset + 2 : f_offset + 2 + len(f_name_bytes)] = f_name_bytes

        name_padded = b".idata\x00\x00"
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            name_padded,
            import_size,
            import_rva,
            import_raw_size,
            import_file_offset,
            0,
            0,
            0,
            0,
            0x40000040,
        )
        sec_headers.extend(sec_hdr)
        all_sec_raw.extend(import_sec_data)
        current_rva += ((import_size + sec_align - 1) // sec_align) * sec_align

    # Optional Header
    opt_hdr = bytearray(224)
    struct.pack_into(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        opt_hdr,
        0,
        0x10B,
        1,
        0,
        0x200,
        0x200,
        0,
        sec_align,
        sec_align,
        0x2000,
        0x400000,
        sec_align,
        file_align,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        current_rva,
        hdr_size,
        0,
        2,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )

    if imports:
        # Import data directory is index 1
        struct.pack_into("<II", opt_hdr, 96 + 8, import_rva, 40)

    headers = (dos_header + pe_sig + coff + opt_hdr + sec_headers).ljust(hdr_size, b"\x00")
    return bytes(headers + all_sec_raw)


def pe_to_ember_record(pe_data: bytes, appeared: str = "2018-05", label: int = 0) -> dict:
    """Generate the exact corresponding EMBER raw JSON record from a PE byte sequence."""
    pe = pefile.PE(data=pe_data)
    try:
        sections = []
        for sec in pe.sections:
            sec_data = sec.get_data()
            sections.append(
                {
                    "name": sec.Name.decode("ascii", errors="ignore").rstrip("\x00"),
                    "size": len(sec_data),
                    "entropy": calculate_entropy(sec_data),
                    "vsize": sec.Misc_VirtualSize,
                    "props": [],
                }
            )

        imports_dict = {}
        total_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii", errors="ignore")
                func_names = []
                for imp in entry.imports:
                    total_imports += 1
                    if imp.name:
                        func_names.append(imp.name.decode("ascii", errors="ignore"))
                imports_dict[dll_name] = func_names

        sha256 = hashlib.sha256(pe_data).hexdigest()

        return {
            "sha256": sha256,
            "appeared": appeared,
            "label": label,
            "general": {
                "size": len(pe_data),
                "vsize": pe.OPTIONAL_HEADER.SizeOfImage,
                "has_debug": 0,
                "exports": 0,
                "imports": total_imports,
            },
            "header": {
                "coff": {
                    "timestamp": pe.FILE_HEADER.TimeDateStamp,
                    "machine": pe.FILE_HEADER.Machine,
                },
                "optional": {
                    "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                },
            },
            "section": {
                "sections": sections,
            },
            "imports": imports_dict,
        }
    finally:
        pe.close()


@pytest.fixture
def sample_config() -> ClarusConfig:
    return load_config()
