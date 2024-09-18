import idc
import idaapi
import ida_bytes
import ida_funcs
import ida_search
import ida_segment
import ida_kernwin
from . import Utils

def check_is_gopclntab(addr):
    ptr = Utils.get_bitness(addr)
    if addr & (ptr.size - 1): return False
    if ida_bytes.get_byte(addr + 7) != ptr.size: return False
    first_entry = ptr.ptr(addr+8+ptr.size)
    first_entry_off = ptr.ptr(addr+8+ptr.size*2)
    addr_func = addr+first_entry_off
    func_loc = ptr.ptr(addr_func)
    if func_loc == first_entry:
        return True
    return False

def check_is_gopclntab16(addr):
    ptr = Utils.get_bitness(addr)
    if addr & (ptr.size - 1): return False
    if ida_bytes.get_byte(addr + 7) != ptr.size: return False
    offset = 8 + ptr.size * 6
    # print(f"{addr+offset:x}")
    first_entry = ptr.ptr(addr+offset) + addr
    # print(f"{first_entry:x}")
    func_loc = ptr.ptr(first_entry)
    struct_ptr = ptr.ptr(first_entry+8) + first_entry
    first_entry = ptr.ptr(struct_ptr)
    if func_loc == first_entry:
        return True
    return False

def check_is_gopclntab18_20(addr):
    # print(f"renzo-----header_addr: {addr:x}")
    ptr = Utils.get_bitness(addr)
    if addr & (ptr.size - 1): return False
    if ida_bytes.get_byte(addr + 7) != ptr.size: return False
    offset = 8 + ptr.size * 7
    first_entry = ptr.ptr(addr+offset) + addr
    # print(f"renzo-----pclntable_addr: {first_entry:x}")
    func_loc = idc.get_wide_dword(first_entry)
    struct_ptr = idc.get_wide_dword(first_entry+4) + first_entry
    first_entry = idc.get_wide_dword(struct_ptr)
    # print(f"renzo-----func_loc: {func_loc:x}")
    # print(f"renzo-----first_entry: {first_entry:x}")
    if func_loc == first_entry:
        return True
    return False

def set_funcname(func_addr, name_addr):
    # if make_funcs == True:
    if True:
        # ida_bytes.del_items(func_addr, 1, ida_bytes.DELIT_DELNAMES)
        ida_bytes.del_items(func_addr)
        ida_funcs.add_func(func_addr)
    nameb = ida_bytes.get_strlit_contents(name_addr, -1, -1)
    if nameb == None:
        print(f"{func_addr:x} ('{idaapi.get_name(func_addr)}') has no name!")
        return
    ida_bytes.del_items(name_addr)
    if ida_bytes.get_byte(name_addr + len(nameb)) == 0:
        ida_bytes.create_strlit(name_addr, len(nameb) + 1, -1)
    else:
        ida_bytes.create_strlit(name_addr, len(nameb), -1)
    name = Utils.relaxName(nameb.decode())
    if name == idaapi.get_name(func_addr): return
    print(f"{func_addr:x} ('{idaapi.get_name(func_addr)}') -> '{nameb.decode()}' ('{name}') ... ", end='')
    if Utils.rename(func_addr, name): print('done')
    else: print('error')

# def rename(beg, ptr, make_funcs = True):
def rename(beg, ptr): # !!! Not tested !!!
    base = beg
    pos = beg + 8 #skip header
    size = ptr.ptr(pos)
    pos += ptr.size
    end = pos + (size * ptr.size * 2)
    # print("%x" % end)
    while pos < end:
        offset = ptr.ptr(pos + ptr.size)
        ptr.maker(pos)         #in order to get xrefs
        ptr.maker(pos+ptr.size)
        pos += ptr.size * 2
        ptr.maker(base+offset)
        func_addr = ptr.ptr(base+offset)
        name_addr = base + idc.get_wide_dword(base+offset+ptr.size)
        set_funcname(func_addr, name_addr)

# def rename16(beg, ptr, make_funcs = True):
def rename16(beg, ptr):
    base = beg
    first_entry = ptr.ptr(base+ptr.size * 6 + 8) + base
    cnt = ptr.ptr(base + 8)
    print('first_entry: ' + hex(first_entry))
    print('function count: %d' % cnt)
    funcname_start = base + 8 + ptr.size *7
    for i in range(cnt):
        struct_ptr = ptr.ptr(first_entry + i*ptr.size*2 + 8) + first_entry
        # print(f"{struct_ptr:x}")
        func_addr = ptr.ptr(first_entry + i*ptr.size*2)
        name_addr = ida_bytes.get_dword(struct_ptr+8) + funcname_start
        set_funcname(func_addr, name_addr)

# def rename20(beg, ptr, make_funcs = True):
def rename20(beg, ptr):
    base = beg
    first_entry = ptr.ptr(base+ptr.size * 7 + 8) + base
    cnt = ptr.ptr(base + 8)
    print('first_entry: ' + hex(first_entry))
    print('function count: %d' % cnt)
    func_entry = ptr.ptr(base + 8 + ptr.size * 2)
    # print("renzo-----func_entry: {:x}".format(func_entry))
    funcname_start = base + ptr.ptr(base + 8 + ptr.size * 3)
    # print("renzo-----funcname_start: {:x}".format(funcname_start))

    for i in range(cnt):
        struct_ptr = idc.get_wide_dword(first_entry + i*4*2 + 4) + first_entry
        # print(f"{struct_ptr:x}")
        func_addr = func_entry + idc.get_wide_dword(first_entry + i*4*2)
        name_addr = idc.get_wide_dword(struct_ptr+4) + funcname_start
        set_funcname(func_addr, name_addr)

info = idaapi.get_inf_structure()
try:
    is_be = info.is_be()
except:
    is_be = info.mf

lookup = "FF FF FF FB 00 00" if is_be else "FB FF FF FF 00 00"
lookup16 = "FF FF FF FA 00 00" if is_be else "FA FF FF FF 00 00"
lookup18 = "FF FF FF F0 00 00" if is_be else "F0 FF FF FF 00 00"
lookup20 = "FF FF FF F1 00 00" if is_be else "F1 FF FF FF 00 00"
magic_bytes_lookup = {}
check_gopclntab = {}
rename_functions = {}
for i in range(16):
    magic_bytes_lookup['go 1.' + str(i)] = bytes.fromhex(lookup)
    check_gopclntab['go 1.' + str(i)] = check_is_gopclntab
    rename_functions['go 1.' + str(i)] = rename
magic_bytes_lookup['go 1.16'] = bytes.fromhex(lookup16)
magic_bytes_lookup['go 1.17'] = bytes.fromhex(lookup16)
magic_bytes_lookup['go 1.18'] = bytes.fromhex(lookup18)
magic_bytes_lookup['go 1.19'] = bytes.fromhex(lookup18)
magic_bytes_lookup['go 1.20'] = bytes.fromhex(lookup20)
check_gopclntab['go 1.16'] = check_is_gopclntab16
check_gopclntab['go 1.17'] = check_is_gopclntab16
check_gopclntab['go 1.18'] = check_is_gopclntab18_20
check_gopclntab['go 1.19'] = check_is_gopclntab18_20
check_gopclntab['go 1.20'] = check_is_gopclntab18_20
rename_functions['go 1.16'] = rename16
rename_functions['go 1.17'] = rename16
rename_functions['go 1.18'] = rename20
rename_functions['go 1.19'] = rename20
rename_functions['go 1.20'] = rename20

def findGoPcLn():
    seg = ida_segment.get_segm_by_name('.gopclntab')
    if seg:
        possible_loc = seg.start_ea
        init_bytes = ida_bytes.get_bytes(possible_loc, 6)
        if init_bytes == bytes.fromhex(lookup20) and check_is_gopclntab18_20(possible_loc):
            # print("Looks like this is go1.20 binary")
            return possible_loc
        elif init_bytes == bytes.fromhex(lookup18) and check_is_gopclntab18_20(possible_loc):
            # print("Looks like this is go1.18 binary")
            return possible_loc
        elif init_bytes == bytes.fromhex(lookup16) and check_is_gopclntab16(possible_loc):
            # print("Looks like this is go1.16 binary")
            return possible_loc
        elif init_bytes == bytes.fromhex(lookup) and check_is_gopclntab(possible_loc):
            return possible_loc
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup20, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        # print(f"found possible 1.20 gopclntab")
        if check_is_gopclntab18_20(possible_loc):
            # print("Looks like this is go1.20 binary")
            return possible_loc
        else:
            # keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup20, 16, idc.SEARCH_DOWN)
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup18, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        # print(f"found possible 1.18 gopclntab")
        if check_is_gopclntab18_20(possible_loc):
            # print("Looks like this is go1.18 binary")
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup18, 16, idc.SEARCH_DOWN)
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        if check_is_gopclntab(possible_loc):
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup, 16, idc.SEARCH_DOWN)
    possible_loc = ida_search.find_binary(0, idc.BADADDR, lookup16, 16, idc.SEARCH_DOWN) #header of gopclntab
    while possible_loc != idc.BADADDR:
        # print(f"found possible 1.16 gopclntab")
        if check_is_gopclntab16(possible_loc):
            # print("Looks like this is go1.16 binary")
            return possible_loc
        else:
            #keep searching till we reach end of binary
            possible_loc = ida_search.find_binary(possible_loc+1, idc.BADADDR, lookup16, 16, idc.SEARCH_DOWN)
    return None

def check_go_version(gopclntab, go_version):
    magic_bytes = ida_bytes.get_bytes(gopclntab, 6)
    if magic_bytes_lookup[go_version] != magic_bytes: return False
    return check_gopclntab[go_version](gopclntab)

def get_inexact_version(gopclntab):
    magic_bytes = ida_bytes.get_bytes(gopclntab, 6)
    for version in magic_bytes_lookup:
        if magic_bytes_lookup[version] == magic_bytes:
            return version
    return None

def renameFunctions(gopclntab, go_version, bt_obj):
    if not check_go_version(gopclntab, go_version):
        print('check version error')
        return
    rename_functions[go_version](gopclntab, bt_obj)
