
import ida_bytes
import idc
import ida_kernwin

def read_varint(addr):
    val = 0
    size = 0
    while True:
        b = ida_bytes.get_byte(addr + size)
        val |= (b & 0x7f) << (size * 7)
        size += 1
        if b & 0x80 == 0: break
    return size, val

def get_typename_varlen(name_addr):
    size, val = read_varint(name_addr + 1)
    return ida_bytes.get_bytes(name_addr + 1 + size, val).decode()


get_typelink_and_types_offset = {}
get_typename = {}
for i in range(16):
    get_typelink_and_types_offset['go 1.' + str(i)] = lambda bt_obj: (bt_obj.size * 30, bt_obj.size * 25)
    get_typename['go 1.' + str(i)] = lambda name_addr: ida_bytes.get_bytes(name_addr + 3, int.from_bytes(ida_bytes.get_bytes(name_addr + 1, 2), 'big')).decode()
get_typelink_and_types_offset['go 1.16'] = lambda bt_obj: (bt_obj.size * 40, bt_obj.size * 35)
get_typelink_and_types_offset['go 1.17'] = lambda bt_obj: (bt_obj.size * 40, bt_obj.size * 35)
get_typelink_and_types_offset['go 1.18'] = lambda bt_obj: (bt_obj.size * 42, bt_obj.size * 35)
get_typelink_and_types_offset['go 1.19'] = lambda bt_obj: (bt_obj.size * 42, bt_obj.size * 35)
get_typelink_and_types_offset['go 1.20'] = lambda bt_obj: (bt_obj.size * 44, bt_obj.size * 37)
get_typename['go 1.16'] = get_typename_varlen
get_typename['go 1.17'] = get_typename_varlen
get_typename['go 1.18'] = get_typename_varlen
get_typename['go 1.19'] = get_typename_varlen
get_typename['go 1.20'] = get_typename_varlen

def parse_type_names_recursive(types_addr, type_offset, version, bt_obj, parsed_types_offset):
    if type_offset in parsed_types_offset: return parsed_types_offset[type_offset]

    type_addr = types_addr + type_offset
    name_addr = ida_bytes.get_dword(type_addr + 4 * bt_obj.size + 8) + types_addr
    type_name = "Unknown"
    try:
        type_name = get_typename[version](name_addr)
    except:
        pass

    parsed_types_offset[type_offset] = type_name
    print('gotype at 0x%x: "%s"' % (type_addr, type_name))
    idc.set_cmt(type_addr, 'gotype "' + type_name + '"', 0)
    ptrtothis_off = ida_bytes.get_dword(type_addr + 4 * bt_obj.size + 12)
    if ptrtothis_off:
        t = parse_type_names_recursive(types_addr, ptrtothis_off, version, bt_obj, parsed_types_offset)
        idc.set_cmt(type_addr + 4 * bt_obj.size + 12, 'ptr_to_this gotype "' + t + '" (0x%x)' % (types_addr + ptrtothis_off), 0)
        # print(hex(type_addr))
    return type_name

def parse_type_names(fmd, version, bt_obj):
    typelink_offset, types_offset = get_typelink_and_types_offset[version](bt_obj)
    typelink_addr = bt_obj.ptr(fmd + typelink_offset)
    type_cnt = bt_obj.ptr(fmd + typelink_offset + bt_obj.size)
    types_addr = bt_obj.ptr(fmd + types_offset)
    parsed_types_offset = {}

    print(hex(types_addr))
    print(hex(typelink_addr))
    print(hex(type_cnt))

    for i in range(type_cnt):
        # assert ida_kernwin.ask_long(i, '12345')
        type_offset = ida_bytes.get_dword(typelink_addr + i * 4)
        parse_type_names_recursive(types_addr, type_offset, version, bt_obj, parsed_types_offset)

def parse_type_name_at(type_addr, fmd, version, bt_obj):
    _, types_offset = get_typelink_and_types_offset[version](bt_obj)
    types_addr = bt_obj.ptr(fmd + types_offset)
    name_addr = ida_bytes.get_dword(type_addr + 4 * bt_obj.size + 8) + types_addr
    type_name = "Unknown"
    try:
        type_name = get_typename[version](name_addr)
    except:
        pass
    ptrtothis_off = ida_bytes.get_dword(type_addr + 4 * bt_obj.size + 12)
    if type_name != "Unknown" and ptrtothis_off:
        idc.set_cmt(type_addr, 'gotype "' + type_name + '" (ptrtothis: 0x%x)' % (ptrtothis_off + types_addr), 0)
    else:
        idc.set_cmt(type_addr, 'gotype "' + type_name + '"', 0)
    return type_name
