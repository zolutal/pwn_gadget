from typing import Optional, List, NamedTuple, Dict, Callable, Tuple
from pwn_gadget.data_types import *
from termcolor import cprint

from pwn import * 

def check_constraints(gdb_api: pwnlib.gdb.Gdb, gadgets: List[Gadget]) -> Optional[int]:
    gadget_fails: List[Tuple[Gadget, List[ConstraintGroup]]] = []
    for gadget in gadgets:
        cg_fails: List[ConstraintGroup] = []
        for constraint_group in gadget.constraint_groups:
            fail, success = check_constraint_group(gdb_api, constraint_group)
            if len(success) == 0:
                cg_fails.append(constraint_group)
        gadget_fails.append((gadget, cg_fails))

    best_gadget: Gadget = None
    least_failed_constraints: List[ConstraintGroup] = None
    for gadget, failed in gadget_fails:
        if least_failed_constraints is None or len(failed) < len(least_failed_constraints):
            best_gadget = gadget
            least_failed_constraints = failed

    for idx, gadget in enumerate(gadgets):
        print(f"Constraints for offset {hex(gadget.address)}:")
        for constraint_group in gadget.constraint_groups:
            if constraint_group in gadget_fails[idx][1]:
                cprint(constraint_group.raw, 'red')
            else:
                cprint(constraint_group.raw, 'green')

    if len(least_failed_constraints) == 0:
        return best_gadget.address

    return None

def check_constraint_group(gdb_api: pwnlib.gdb.Gdb, constraint_group: ConstraintGroup) -> Tuple[List[Constraint], List[Constraint]]:
    failed: List[Constraint] = []
    succeeded: List[Constraint] = []
    for constraint in constraint_group.constraints:
        try:
            res: str = gdb_api.execute(f"p {constraint.arg1}", to_string=True)
        except:
            failed.append(constraint)
            continue
        parsed_res: str = res.split("=")[1].strip()
        #TODO handle xmm better(?)
        if "xmm" in constraint.arg1:
            parsed_res = res.split(",")[1][:-2]
        value = int(parsed_res, 16)
        
        if constraint.operation.eval(value, constraint.arg2):
            succeeded.append(constraint)
            break # if one constraint succeeded in the constraint group, no need to check the rest
        else:
            failed.append(constraint)
    return failed, succeeded