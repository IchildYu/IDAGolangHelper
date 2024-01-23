
from . import Gopclntab
from . import Types

def apply_patches(GolangHelper):
    for i in ['go 1.21', 'go 1.22']:
        GolangHelper.VERSIONS[-1].append(i)
        Gopclntab.magic_bytes_lookup[i] = Gopclntab.magic_bytes_lookup['go 1.20']
        Gopclntab.check_gopclntab[i] = Gopclntab.check_gopclntab['go 1.20']
        Gopclntab.rename_functions[i] = Gopclntab.rename_functions['go 1.20']
        Types.get_typelink_and_types_offset[i] = Types.get_typelink_and_types_offset['go 1.20']
        Types.get_typename[i] = Types.get_typename['go 1.20']
