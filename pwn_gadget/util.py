from pwn_gadget.logging import Logging as log
from typing import List, Dict, Optional
from functools import reduce
from os.path import exists, expanduser

import subprocess

class MemoryPerm():
    READ = 1
    WRITE = 2
    EXEC = 4

    str_perm_map: Dict[str, int] = {
        'r': READ,
        'w': WRITE,
        'x': EXEC
    }

    def __init__(self, perm_str: str):
        self.value: int = 0
        self.value = reduce(lambda x, y: x | y, [self.str_perm_map.get(perm, 0) for perm in perm_str])

        
def check_memory_permissions(address: int, perm: int, gdb_api) -> bool:
    """
    param gdb_api: The current gdb api to execute commands through 
    param address: The address of memory to check the permissions for 
    param perm: An integer representing the permission to check for
    return: True if perm in permissions for address, else False
    """
    mappings_raw: str = gdb_api.execute("info proc mappings", to_string=True)

    if 'Perms' not in mappings_raw:
        log.warn("The version of gdb you are using does not display permissions in the 'info proc mappings' command output, unable to check memory permissions")
        return False

    mapping_lines: List[str] = mappings_raw.strip().split("\n")[4:]
    mapping_split: List[List[str]] = [' '.join(line.split(" ")).split() for line in mapping_lines]

    for mapping in mapping_split:
        # mapping: {Start Addr}, {End Addr}, {Size}, {Offset}, {Perms}, {objfile}
        if address in range(int(mapping[0], 16), int(mapping[1], 16)):
            mapping_perm: int = MemoryPerm(mapping[4]).value
            if mapping_perm & perm != 0: return True
    return False

def get_constraints_list(path: str, level: int) -> List[str]:
    if exists(expanduser(path)):
        return subprocess.check_output(['one_gadget', f'-l{level}', path]).decode().split('\n\n')
    raise Exception(f"Path '{path}' is invalid")

def get_current_pc(gdb_api) -> int: 
    return int(gdb_api.execute("p/x $pc", to_string=True).split(" ")[-1], 16)

def get_libc_path(gdb_api) -> int: 
    output_raw: str = gdb_api.execute("info sharedlibrary libc", to_string=True).strip()
    if "No shared libraries matched." in output_raw:
        log.error("No shared libraries found in memory containing string 'libc', please specify the path and run again")
        exit()
    output_split: List[str] = output_raw.split("\n") 
    return output_split[-1].strip().split(' ')[-1]

def is_alive(gdb_api) -> bool:
    """Check if GDB is running."""
    try:
        return gdb_api.selected_inferior().pid > 0
    except Exception:
        return False