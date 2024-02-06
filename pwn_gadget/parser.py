from typing import Optional, List, Union
from pwn_gadget.util import MemoryPerm
from pwn_gadget.data_types import *
from pwn_gadget.logging import Logging as log

import re

def parse_constraints_list(constraints_list: List[str]) -> List[Gadget]:
    gadgets: List[Gadget] = []

    raw_constraints: str
    for raw_constraints in constraints_list:
        lines = raw_constraints.rstrip().split("\n")

        address = int(lines[0].split(" ")[0], 16)

        constraint_groups: List[ConstraintGroup] = []
        for constraint in lines[2:]:
            split = [l.strip() for l in constraint.split("||")]
            constraints: List[Constraint] = parse_constraint(split)
            constraint_groups.append(ConstraintGroup(constraints, constraint))
        gadgets.append(Gadget(address, constraint_groups))
    return gadgets

def parse_constraint(constraint: List[str]) -> List[Constraint]:
    parsed: List[Constraint] = []
    for c in constraint:
        arg1: str
        arg2: Optional[Union[str, int]] = None
        operation: Operator
        if c.endswith("is writable"):
            arg1 = c.split(" ")[1]
            arg2 = MemoryPerm.WRITE
            operation = Operator("wr")
        elif c.endswith("are writable"):
            c = c.split('addresses ')[1]
            c = c.split(' are writable')[0]
            cons = c.split(', ')[0]
            for con in cons:
                arg1 = parse_gdb_arg(con)
                arg2 = int(MemoryPerm.WRITE)
                operation = Operator("wr")
                parsed.append(Constraint(arg1, arg2, operation, c))
            continue
        elif c.startswith("writable:"):
            arg1 = c.split(" ")[1]
            arg2 = MemoryPerm.WRITE
            operation = Operator('wr')
        elif '&' in c: # Handle $rsp & 0xf == NULL
            comps = c.split(" ")
            operation = Operator(comps[3])
            arg1 = " ".join(comps[0:3])
            arg2 = comps[4].replace('NULL', '0')
        elif c.endswith('argv'): # 'is a valid argp'
            arg1 = c.split("}")[0] + "}"
            arg2 = 0
            operation = Operator("argv")
        elif c.endswith('envp'): # 'is a valid envp'
            arg1 = c.split("}")[0] + "}"
            arg2 = 0
            operation = Operator("envp")
        else:
            comps = c.split(" ")
            operation = Operator(comps[1])
            arg1 = comps[0]
            arg2 = comps[2].replace('NULL', '0')
        arg1 = parse_gdb_arg(arg1)
        arg2 = int(arg2)
        parsed.append(Constraint(arg1, arg2, operation, c))
    return parsed

def parse_gdb_arg(arg: str) -> str:
    """
    Parse argument to valid gdb print format
    """
    # Extract type
    arg_type: str = "(unsigned long)"
    m = re.search("\([a-zA-Z]\d*\)", arg) # \([a-zA-Z]\d{2}\)
    if m is not None:
        found_type = type_map.get(m.group(0))
        if found_type:
            arg_type = found_type
        else:
            log.error("Unhandled type '%s' encountered in one_gadget constraint, treating as unsigned long" % found_type)
            found_type = "(unsigned long)"
        arg = arg.replace(found_type, "")

    # Extract number of derefs
    derefs_ct: int = arg.count("[")
    derefs: str = '*'*derefs_ct + "(long" + '*'*derefs_ct + ')'
    arg = arg.replace("[", "").replace("]", "")

    reg: str = arg.split(" ")[0]
    extra_ops: str = " ".join(arg.split(" ")[1:])
    gdb_arg: str = ""
    if "xmm" in reg:
        #TODO handle xmm better(?)
        xmm_type: str = "v2_int64"
        gdb_arg = arg_type + derefs + f"(${reg}.{xmm_type})" + extra_ops
    else:
        gdb_arg = derefs + arg_type + f"(${reg}) " + extra_ops
    return gdb_arg

