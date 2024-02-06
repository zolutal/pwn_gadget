from typing import Optional, List, NamedTuple, Dict, Callable, Tuple
from pwn_gadget.data_types import *
from pwn_gadget.logging import Color, cprint

def check_constraints(gdb_api, gadgets: List[Gadget]) -> Optional[int]:
    gadget_stats: List[Tuple[Gadget, List[Tuple[Result, ConstraintGroup]]]] = []
    for gadget in gadgets:
        cg_stats: List[Tuple[Result, ConstraintGroup]] = []
        for constraint_group in gadget.constraint_groups:
            sat, unknown, unsat = check_constraint_group(gdb_api, constraint_group)
            if len(sat) > 0:
                result = Result.Sat
            elif len(unknown) > 0:
                result = Result.Unknown
            else:
                result = Result.Unsat
            cg_stats += [(result, constraint_group)]
        gadget_stats += [(gadget, cg_stats)]

    best_gadget: Gadget = None
    least_fail_unk_constraints = None
    for gadget, cg_stats in gadget_stats:
        fails = len([cg for res, cg in cg_stats if res == Result.Unsat])
        unk = len([cg for res, cg in cg_stats if res == Result.Unknown])
        if least_fail_unk_constraints is None or fails + unk < least_fail_unk_constraints:
            least_fail_unk_constraints = fails + unk
            best_gadget = gadget

    for gadget, cg_stats in gadget_stats:
        print(f"Constraints for offset {hex(gadget.address)}:")
        for result, cg in cg_stats:
            if result == Result.Unknown:
                cprint(cg.raw, Color.YELLOW)
            elif result == Result.Unsat:
                cprint(cg.raw, Color.RED)
            elif result == Result.Sat:
                cprint(cg.raw, Color.GREEN)

    if least_fail_unk_constraints == 0:
        return best_gadget.address

    return None

def check_constraint_group(gdb_api, constraint_group: ConstraintGroup) -> Tuple[List[Constraint], List[Constraint], List[Constraint]]:
    sat: List[Constraint] = []
    unsat: List[Constraint] = []
    unknown: List[Constraint] = []
    for constraint in constraint_group.constraints:
        try:
            res: str = gdb_api.execute(f"p {constraint.arg1}", to_string=True)
        except:
            unknown.append(constraint)
            continue
        parsed_res: str = res.split("=")[1].strip()
        #TODO handle xmm better(?)
        if "xmm" in constraint.arg1:
            parsed_res = res.split(",")[1][:-2]
        value = int(parsed_res, 16)

        match constraint.operation.eval(value, constraint.arg2, gdb_api):
            case Result.Sat | True:
                sat.append(constraint)
                break # if one constraint succeeded in the constraint group, no need to check the rest
            case Result.Unknown:
                unknown.append(constraint)
            case Result.Unsat | False:
                unsat.append(constraint)
    return sat, unknown, unsat
