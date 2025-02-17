from archinfo import Endness
MIN_STR_LEN = 1
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`?|<>{}[] \""
SEPARATOR_CHARS = ('-', '_')

# the interested sink functions
SINKS = ['popen', 'system', 'doSystemCmd', 'doSystembk', 'doSystem', 'COMMAND', '_popen', '_system','__system', '_doSystemCmd', '_doSystembk', '_doSystem', '_COMMAND', 
'AES_set_encrypt_key', 'AES_set_decrypt_key', 'EVP_DecryptInit_ex', 'EVP_EncryptInit_ex', 'DES_set_key_checked', 'AES_cbc_encrypt', '_AES_set_encrypt_key', '_AES_set_decrypt_key', '_EVP_DecryptInit_ex', '_EVP_EncryptInit_ex', '_DES_set_key_checked', '_AES_cbc_encrypt', 
'sprintf', 'snprintf', '_sprintf', '_snprintf',
'___system', 'bstar_system', 'doShell', 'twsystem', 'CsteSystem', 'cgi_deal_popen',
'ExeCmd', 'ExecShell', 'exec_shell_popen', 'exec_shell_popen_str',
'nvram_safe_set', 'nvram_bufset', 'setenv',
'strcpy', 'memcpy', 'strcat','strncpy',
'fwrite','execve']

_ordered_argument_regs_names = {
    'ARMEL': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12'],
    'AARCH64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'],
    'MIPS32': ['a0', 'a1', 'a2', 'a3'],
}

def get_mem_string(mem_bytes, extended=False):
    """
    Return the set of consecutive ASCII characters within a list of bytes

    :param mem_bytes: list of bytes
    :param extended: use extended list of characters
    :return: the longest string found
    """

    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS
    for c in mem_bytes:
        c_ascii = chr(c)
        if c_ascii not in chars:
            break
        tmp += c_ascii
    return tmp

def get_string(p, mem_addr, extended=False):
    """
    Get string from a memory address
    :param p: angr project
    :param mem_addr: memory address
    :param extended: consider extended characters
    :return: the candidate string
    """

    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)

    # get string representation at mem_addr
    try:
        cnt = p.loader.memory.load(mem_addr, STR_LEN)
    except KeyError:
        # this memory address is not readable
        cnt = ''
    string_1 = get_mem_string(cnt, extended=extended)
    if string_1 is None:
        string_1=''
    string_2 = ''
    string_3 = ''
    string_4 = ''

    # check whether the mem_addr might contain an address
    # or the string is referenced by offset to the .got (yep, this happens)
    try:
        endianness = 'little' if p.arch.memory_endness == Endness.LE else 'big'
        ind_addr = int.from_bytes(p.loader.memory.load(mem_addr, p.arch.bytes), endianness)
        if bin_bounds[0] <= ind_addr <= bin_bounds[1]:
            cnt = p.loader.memory.load(ind_addr, STR_LEN)
            string_2 = get_mem_string(cnt)

        tmp_addr = (ind_addr + p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
        cnt = p.loader.memory.load(tmp_addr, STR_LEN)
        string_3 = get_mem_string(cnt)

        tmp_addr = (mem_addr + p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
        cnt = p.loader.memory.load(tmp_addr, STR_LEN)
        string_4 = get_mem_string(cnt)

    except KeyError as e:
        pass

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    candidate2 = string_3 if len(string_3) > len(string_4) else string_4
    candidate = candidate if len(candidate) > len(candidate2) else candidate2

    return candidate if len(candidate) >= MIN_STR_LEN else ''

def arg_reg_name(p, idx):
    """
    Gets a register name by the argument register index
    :param p: the project
    :param idx: the index of the argument register
    :return: the name of the register
    """
    return _ordered_argument_regs_names[p.arch.name][idx]

def arg_reg_names(p, n=-1):
    """
    Gets the first n argument register names. If n=-1, it will return all argument registers
    :param p: the project
    :param n: the number of elements to retrieve
    :return: the name of the register
    """
    if n < 0:
        return _ordered_argument_regs_names[p.arch.name]
    return _ordered_argument_regs_names[p.arch.name][:n]

def get_arity(p, b_addr):
    """
    Retrieves the arity by inspecting a funciton call
    :param p: angr project
    :param b_addr: basic block address
    :return: arity of the function
    """
    return len(get_ord_arguments_call(p, b_addr))


def get_ord_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
    so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.
    :param p: angr project
    :param b_addr: basic block address
    :return: the arguments of a function call
    """
    set_params = []
    b = p.factory.block(b_addr)
    for reg_name in arg_reg_names(p):
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and p.arch.register_names[s.offset] == reg_name]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params

def get_arguments_call_with_instruction_address(p, b):
    """
    Retrieves the list of instructions setting arguments for a function call with the corresponding function address.
    It checks the arguments in order so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.
    :param p: angr project
    :param b: basic block
    :return: a list of (instruction_address and the arguments of a function call)
    """
    set_params = []
    for reg_name in _ordered_argument_regs_names[p.arch.name]:
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and p.arch.register_names[s.offset] == reg_name]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        # find the address of this instruction
        stmt_idx = b.vex.statements.index(put_stmt)
        inst_addr = [x.addr for x in b.vex.statements[:stmt_idx] if hasattr(x, 'addr')][-1]

        set_params.append((inst_addr, put_stmt))

    return set_params