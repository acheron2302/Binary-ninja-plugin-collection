#
#
def sort_ref(ref_list):
    # take in the refs list return the address to convert to nop
    push_address = []
    call_address = []
    for each_ref in ref_list:
        func = each_ref.function
        llil = func.llil
        llil_ssa = llil.ssa_form    

        index = llil.get_instruction_start(each_ref.address)
        ssa_index = llil[index].ssa_form.instr_index
        if llil_ssa[ssa_index].operation == LowLevelILOperation.LLIL_CALL_SSA:
            # Deal with it when it is call instruction
            call_address.append(llil_ssa[ssa_index].address)
            temp_address = llil_ssa.get_ssa_reg_definition(llil_ssa[ssa_index].prefix_operands[9]).address
            push_address.append(temp_address)
            continue
             
        dest_instr = llil_ssa[ssa_index].dest
        reg_ref = llil_ssa.get_ssa_reg_uses(dest_instr)
        
        for ll_instr in reg_ref:
            if ll_instr.operation != LowLevelILOperation.LLIL_CALL_SSA:
                continue
            
            call_address.append(ll_instr.address)
            temp_address = llil_ssa.get_ssa_reg_definition(ll_instr.prefix_operands[7]).address
            push_address.append(temp_address)
    return push_address, call_address

def main():
    llil_ssa = current_llil.ssa_form

    # Get the OutputDebugStringW symbol
    outputdebug_addr = bv.get_symbol_by_raw_name("OutputDebugStringW")
    refs_gen = bv.get_code_refs(outputdebug_addr.address)
    push_address, call_address = sort_ref(refs_gen)

    log_info(call_address)
    log_info(push_address)

    for i in range(len(call_address)):
        bv.convert_to_nop(call_address[i])
        bv.convert_to_nop(push_address[i])

main()