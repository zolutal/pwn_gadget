from pwn_gadget.util import get_current_pc, get_constraints_list
from pwn_gadget.parser import parse_constraints_list
from pwn_gadget.checking import check_constraints
from pwn_gadget.logging import Logging as log
from pwn_gadget.data_types import Gadget

from typing import Optional, List

def find_gadget(gdb_api, path: str, address: Optional[int] = None, cache: bool = True) -> Optional[int]:
    """
    param gdb: The gdb api returned by gdb.attach(process, api=True)
    param path: The path to the libc to run one_gadget against
    param address: The address to check the constraints at, default current address
    param cache: Return cached gadget, default True
    return: Address of satisfiable gadget or None
    """
    # wait is only necessary (and only implemented) for pwntools use case
    try:
        gdb_api.wait()
    except:
        pass

    log.info("Finding one gadgets")
    current_pc = get_current_pc(gdb_api)
    log.info("Current program counter: %s" % hex(current_pc))
    constraints_list: List[str] = get_constraints_list(path)
    log.info("Found %d one gadgets" % len(constraints_list))
    constraint_groups: List[Gadget] = parse_constraints_list(constraints_list)
    log.info("Performing gdb operations to evaluate constraints")
    valid_constraint: Optional[int] = check_constraints(gdb_api, constraint_groups)
    if valid_constraint is not None:
        log.info("Found satisfiable one gadget at address 0x%x" % valid_constraint)
    else:
        log.info("Failed to find a satisfiable one gadget")
    return valid_constraint
