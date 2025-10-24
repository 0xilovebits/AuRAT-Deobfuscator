import lief
import os
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
from utils import (
    find_obfuscated_imports,
    resolve_obfuscated_imports,
    update_api_addresses,
    print_imports,
    PatternType,
    spaced_mov_call_assemble,
    patch_special_resolver,
    add_function,
)


def get_va_by_name(binary, func_name):
    for imported_lib in binary.imports:
        for imported_func in imported_lib.entries:
            if imported_func.name and imported_func.name == func_name:
                va = binary.optional_header.imagebase + imported_func.iat_address
                return va
    return None


def clean_imports(binary):
    binary.remove_all_libraries()


def main():
    input_file = "obfuscated.exe"
    output_dir = "output"
    output_file = os.path.join(output_dir, "deobfuscated.exe")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    try:
        binary = lief.PE.parse(input_file)
        if not binary:
            raise Exception("Binary is None")
    except Exception as e:
        print(f"Failed to load PE file '{input_file}': {e}")
        return 1
    clean_imports(binary)

    print("Rebuild Binary With 0 Libraries")
    builder = lief.PE.Builder(binary)
    builder.build_imports(True)
    builder.patch_imports(True)
    builder.build()
    builder.write(output_file)
    binary = lief.PE.parse(output_file)

    code_section = binary.get_section(".text")
    code_bytes = bytes(code_section.content)
    obf_imports = find_obfuscated_imports(
        code_bytes, (code_section.virtual_address + binary.imagebase)
    )
    print_imports(obf_imports)

    print("Resolving imports and adding functions...\n")
    resolve_obfuscated_imports(obf_imports, binary)
    add_function("user32.dll", "wsprintfA", binary)
    add_function("Shell32.dll", "IsUserAnAdmin", binary)
    add_function("Userenv.dll", "GetUserProfileDirectoryA", binary)
    print("Rebuilding binary with imports...")
    builder = lief.PE.Builder(binary)
    builder.build_imports(True)
    builder.patch_imports(True)
    builder.build()
    builder.write(output_file)

    print("Reloading binary for final patching...")
    binary = lief.PE.parse(output_file)
    update_api_addresses(obf_imports, binary)

    print("Patching Started :\n")
    for ObfImport in obf_imports:
        if ObfImport.type == PatternType.DIRECT_MOV_CALL:
            machine_code = bytearray()
            total_size = 0
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
            except KsError as e:
                print(f"Failed to initialize Keystone: {e}")
                return -1

            disp = ObfImport.resolved_api - (ObfImport.start_address + 7)
            encoding, count = ks.asm(
                f"mov rax, qword ptr [rip + {disp}]",
                ObfImport.start_address,
            )
            size = len(encoding)
            total_size += size
            machine_code.extend(encoding)
            patch_size = len(machine_code)
            padding_size = ObfImport.end_address - ObfImport.start_address - patch_size
            binary.patch_address(ObfImport.start_address, list(machine_code))
            if padding_size > 0:
                padding = [0x90] * padding_size
                binary.patch_address(ObfImport.start_address + patch_size, padding)
            print(f"\tPatched DIRECT_MOV_CALL : {ObfImport}")

        elif ObfImport.type == PatternType.SPACED_MOV_CALL:
            machine_code = spaced_mov_call_assemble(ObfImport)
            binary.patch_address(ObfImport.start_address, list(machine_code))
            print(f"\tPatched SPACED_MOV_CALL : {ObfImport}")
    print("\tPatched Special Resolvers")
    patch_special_resolver(
        binary, 0x1800010B0, 0x180001154, get_va_by_name(binary, "HeapAlloc")
    )

    patch_special_resolver(
        binary, 0x180001160, 0x1800012C7, get_va_by_name(binary, "wsprintfA")
    )
    patch_special_resolver(
        binary, 0x1800016F0, 0x180001847, get_va_by_name(binary, "IsUserAnAdmin")
    )
    patch_special_resolver(
        binary,
        0x1800019B0,
        0x180001B07,
        get_va_by_name(binary, "GetUserProfileDirectoryA"),
    )
    print("\n")
    print("Writing final patched binary...")
    builder = lief.PE.Builder(binary)
    builder.build_imports(False)
    builder.patch_imports(False)
    builder.build()
    builder.write(output_file)

    print("Done")


main()
