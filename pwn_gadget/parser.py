from typing import Optional, List, NamedTuple, Dict, Callable, Tuple
from pwn_gadget.data_types import *

import re

def parse_constraints_list(constraints_list: List[str]) -> List[Gadget]:
    gadgets: List[Gadget] = []

    raw_constraints: str
    for raw_constraints in constraints_list:
        lines = raw_constraints.split("\n")[:-1]

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
        arg2: Optional[str] = None
        operation: Operator
        if c.endswith("is writable"):
            arg1 = c.split(" ")[1]
            operation = Operator("wr")
        elif c.startswith("writable:"):
            arg1 = c.split(" ")[1]
            operation = Operator('wr')
        elif '&' in c: # Handle $rsp & 0xf == NULL
            comps = c.split(" ")
            operation = Operator(comps[3])
            arg1 = " ".join(comps[0:3])
            arg2 = comps[4]
        else:
            comps = c.split(" ")
            operation = Operator(comps[1])
            arg1 = comps[0]
            arg2 = comps[2]
        arg1 = parse_gdb_arg(arg1)
        arg2 = int(arg2.replace('NULL', '0')) if arg2 is not None else arg2
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
        found_type = m.group(0)
        arg_type = type_map.get(found_type)
        arg = arg.replace(found_type, "")

    # Extract number of derefs
    derefs: str = "".join(["*" for c in arg if c == "["])
    arg = arg.replace("[", "").replace("]", "")

    reg: str = arg.split(" ")[0]
    extra_ops: str = " ".join(arg.split(" ")[1:])
    gdb_arg: str = ""
    if "xmm" in reg:
        #TODO handle xmm better(?)
        xmm_type: str = "v2_int64"
        gdb_arg = derefs + f"(${reg}.{xmm_type})" + extra_ops
    else:
        gdb_arg = derefs + arg_type + f"(${reg}) " + extra_ops
    return gdb_arg

