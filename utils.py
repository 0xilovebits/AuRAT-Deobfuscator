import lief
import os
from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64, CsError, CS_OP_REG, CS_OP_IMM
from capstone.x86_const import X86_REG_ECX
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import List
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError

RESOLVERS = {
    "kernel32": 0x180001000,
    "user32": 0x180001160,
    "msvcrt": 0x1800012D0,
    "advapi32": 0x180001430,
    "Wtsapi32": 0x180001590,
    "ws2_32": 0x180001850,
}
MAX_SPACED_INS = 20

class PatternType(Enum):
    DIRECT_MOV_CALL = auto()
    # Pattern 1:
    # mov ecx, <hash>
    # call resolver
    # => move hash to ECX then call the resolver

    SPACED_MOV_CALL = auto()
    # Pattern 2:
    # mov ecx, <hash>
    # <some other instructions>
    # call resolver
    # => Same but there are random instructions between mov and call resolver

    DIRECT_CALL = auto()  # The way for deobfuscate this is only patch the actual function

    # Pattern 3:
    # call resolver
    # => call to an resolver get specified api
    def __str__(self):
        return self.name


@dataclass
class ObfuscatedImport:
    start_address: int = 0
    end_address: int = 0
    type: PatternType = -1
    hash: int = 0
    resolved_api: int = 0
    mov_instruction_address: int = 0
    call_instruction_address: int = 0
    between_instructions: List[CsInsn] = field(default_factory=list)

    def __str__(self):
        return (
            f"ObfImport[type={self.type}, hash=0x{self.hash:08X}, "
            f"start=0x{self.start_address:X}, end=0x{self.end_address:X}]"
        )


def add_library(dll_name, binary: lief.Binary):
    if binary.has_import(dll_name):
        print(f"\tLibrary {dll_name} already imported")
        return binary.get_import(dll_name)
    import_dll = binary.add_library(dll_name)
    print(f"\tAdded library: {dll_name} (no functions imported yet)")
    return import_dll


def add_function(dll_name, function_name, binary: lief.Binary):
    if not binary.has_import(dll_name):
        import_dll = add_library(dll_name, binary)
    else:
        import_dll = binary.get_import(dll_name)
    existing_imports = {entry.name for entry in import_dll.entries}
    if function_name in existing_imports:
        print(f"\tFunction {function_name} already imported from {dll_name}")
        return True
    import_dll.add_entry(function_name)
    print(f"\tAdded function: {function_name} from {dll_name}")
    return True


def get_function_by_hash(hash_value):
    for dll_name in RESOLVERS.keys():
        dll_filename = f"{dll_name}.dll"
        for path in os.environ["PATH"].split(os.pathsep):
            full_path = os.path.join(path, dll_filename)
            if os.path.exists(full_path):
                try:
                    dll_binary = lief.PE.parse(full_path)
                    for export in dll_binary.exported_functions:
                        if export.name and hash_string(export.name) == hash_value:
                            return dll_filename, export.name
                except Exception:
                    continue
    return None, None


def find_obfuscated_imports(TextSectionContent, VirtualAddress):
    imports = []

    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
        disassembler.detail = True
    except CsError as e:
        print(f"Capstone init failed: {e}")
        return imports

    disasm = list(disassembler.disasm(TextSectionContent, VirtualAddress))
    disasm_count = len(disasm)
    i = 0

    while i < disasm_count:
        ins = disasm[i]
        if (
            ins.mnemonic == "mov"
            and len(ins.operands) >= 2
            and ins.operands[0].type == CS_OP_REG
            and ins.operands[1].type == CS_OP_IMM
            and ins.operands[0].reg == X86_REG_ECX
        ):
            hash_value = ins.operands[1].imm
            found_call = False
            between_instructions = []
            for j in range(i + 1, min(disasm_count, i + 1 + MAX_SPACED_INS)):
                next_ins = disasm[j]
                if next_ins.mnemonic == "call" and len(next_ins.operands) > 0:
                    if (
                        next_ins.operands[0].type == CS_OP_IMM
                        and next_ins.operands[0].imm in RESOLVERS.values()
                    ):
                        obf_import = ObfuscatedImport()
                        obf_import.hash = hash_value
                        obf_import.mov_instruction_address = ins.address
                        obf_import.call_instruction_address = next_ins.address

                        if j == i + 1:
                            obf_import.type = PatternType.DIRECT_MOV_CALL
                            obf_import.start_address = ins.address
                            obf_import.end_address = next_ins.address + next_ins.size
                        else:
                            obf_import.type = PatternType.SPACED_MOV_CALL
                            obf_import.start_address = ins.address
                            obf_import.end_address = next_ins.address + next_ins.size
                            obf_import.between_instructions = between_instructions

                        imports.append(obf_import)
                        found_call = True
                        i = j
                        break
                    else:
                        break
                else:
                    between_instructions.append(disasm[j])
            if found_call:
                continue
        i += 1
    return imports


def print_imports(imports):
    print(f"Found {len(imports)} obfuscated imports:")
    for i, imp in enumerate(imports):
        print(f"\t{i + 1}: {imp}")


def hash_string(name):
    nameb = name.encode()
    hash = 0
    for byte in nameb:
        hash *= 0x21
        hash += byte
    return hash & 0xFFFFFFFF


def resolve_obfuscated_imports(obfuscated_imports, binary):
    for obf_import in obfuscated_imports:
        found = False
        for dll in binary.imports:
            for entry in dll.entries:
                if hash_string(entry.name) == obf_import.hash:
                    found = True
                    # print(f"Already imported: {entry.name}")
                    break
            if found:
                break
        if not found:
            dll_name, func_name = get_function_by_hash(obf_import.hash)
            if dll_name and func_name:
                add_function(dll_name, func_name, binary)
                # print(f"Added: {func_name} from {dll_name}")


def update_api_addresses(obfuscated_imports, binary):
    for obf_import in obfuscated_imports:
        for dll in binary.imports:
            for entry in dll.entries:
                if hash_string(entry.name) == obf_import.hash:
                    obf_import.resolved_api = (
                        binary.optional_header.imagebase + entry.iat_address
                    )
                    print(f"\tResolved: {entry.name} -> 0x{obf_import.resolved_api:x}")
                    break


def spaced_mov_call_assemble(ObfImport: ObfuscatedImport):
    machine_code = bytearray()
    total_size = 0

    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    except KsError as e:
        print(f"Failed to initialize Keystone: {e}")
        return bytearray()
    instructions_list = []
    for ins in ObfImport.between_instructions:
        instructions_list.append(f"{ins.mnemonic} {ins.op_str}")
    for ins in instructions_list:
        encoding, count = ks.asm(ins, ObfImport.start_address + total_size)
        total_size += len(encoding)
        machine_code.extend(encoding)
    disp = ObfImport.resolved_api - (ObfImport.start_address + total_size + 7)
    encoding, count = ks.asm(
        f"mov rax, qword ptr [rip + {disp}]", ObfImport.start_address + total_size
    )
    total_size += len(encoding)
    machine_code.extend(encoding)
    padding_size = ObfImport.end_address - ObfImport.start_address - len(machine_code)
    if padding_size > 0:
        machine_code.extend([0x90] * padding_size)
    return machine_code


def patch_special_resolver(
    binary: lief.Binary, start_address: int, end_address: int, rax_value: int
):
    try:
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        patch_code = bytearray()
        disp = rax_value - (start_address + 7)
        encoding, _ = ks.asm(f"mov rax, qword ptr [rip + {disp}]", start_address)
        patch_code.extend(encoding)
        encoding, _ = ks.asm("ret", start_address + len(patch_code))
        patch_code.extend(encoding)
        total_size = end_address - start_address
        if len(patch_code) < total_size:
            patch_code.extend([0x90] * (total_size - len(patch_code)))
        binary.patch_address(start_address, list(patch_code))
        return True
    except Exception:
        return False
