from idaapi import *
from idautils import *
from idc import *

EGG = "network_send_broadcast" # needs unique xref to "rev_set_handler"
SET_HANDLER_CALL = next(XrefsTo([s for s in Strings() if str(s) == EGG][0].ea)).frm + 5
SET_HANDLER_ADDR = get_operand_value(SET_HANDLER_CALL, 0)

for xref in XrefsTo(SET_HANDLER_ADDR):
    vm_handler = get_operand_value(get_arg_addrs(xref.frm)[1], 0)
    vm_func = get_operand_value(get_arg_addrs(xref.frm)[0], 0)
    vm_func_name = get_strlit_contents(vm_func, -1, STRTYPE_C).decode("utf8")
    set_name(vm_handler, f"rev_{vm_func_name}_handler")
    print(f"{hex(vm_handler)} -> {vm_func_name}")