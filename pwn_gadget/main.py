from pwn_gadget.util import get_current_pc, get_constraints_list, get_libc_path, is_alive
from pwn_gadget.parser import parse_constraints_list
from pwn_gadget.checking import check_constraints
from pwn_gadget.logging import Logging as log
from pwn_gadget.data_types import Gadget

from argparse import ArgumentParser, Namespace
from typing import Optional, List

def find_gadget(gdb_api, path: Optional[str] = None, level: int = 0) -> Optional[int]:
    """
    param gdb: The gdb api returned by gdb.attach(process, api=True)
    param path: The path to the libc to run one_gadget against
    return: Address of satisfiable gadget or None
    """
    # TODO maybe this try catch should be made into a decorator
    try:
        if not is_alive(gdb_api):
            raise Exception("No active debugging session")
            
        # wait() is only necessary (and only implemented) for pwntools use case
        try:
            gdb_api.wait()
        except:
            pass

        if not path:
            path = get_libc_path(gdb_api)

        log.info("Finding one gadgets for libc at %s" % path)
        current_pc = get_current_pc(gdb_api)
        log.info("Current program counter: %s" % hex(current_pc))
        constraints_list: List[str] = get_constraints_list(path, level)
        log.info("Found %d one gadgets" % len(constraints_list))
        constraint_groups: List[Gadget] = parse_constraints_list(constraints_list)
        log.info("Performing gdb operations to evaluate constraints")
        valid_constraint: Optional[int] = check_constraints(gdb_api, constraint_groups)
        if valid_constraint is not None:
            log.info("Found satisfiable one gadget at address 0x%x" % valid_constraint)
        else:
            log.info("Failed to find a satisfiable one gadget")
            if level == 0: log.info("Consider increasing the output level by specifying --level 1 to evaluate more gadgets")
        return valid_constraint
    except Exception as e:
        log.error(str(e))

def parse_args(args: List[str]) -> Namespace:
    parser: ArgumentParser =  ArgumentParser("pwn_gadget")
    parser.add_argument('path', nargs='?', type=str, help="The path to the libc file to run one_gadget on. If unspecified, the libc loaded by the current debug target will be used.")
    parser.add_argument('-l', '--level', type=int, default=0, help="sets the level parameter of one_gadget")

    return parser.parse_args(args)


def command(gdb, args_str: str):
    args_str = args_str.strip()
    args = args_str.split() if args_str else []
    try:
        ns: Namespace = parse_args(args)
        find_gadget(gdb, ns.path, ns.level)
    except SystemExit: # ArgParse --help...
        pass
    except RuntimeWarning: # ArgParse on --help...
        pass