
from . import Gopclntab
from . import Types

def apply_patches(GolangHelper):
    GolangHelper.VERSIONS[-1].append('go 1.21')
    Gopclntab.magic_bytes_lookup['go 1.21'] = Gopclntab.magic_bytes_lookup['go 1.20']
    Gopclntab.check_gopclntab['go 1.21'] = Gopclntab.check_gopclntab['go 1.20']
    Gopclntab.rename_functions['go 1.21'] = Gopclntab.rename_functions['go 1.20']
    Types.get_typelink_and_types_offset['go 1.21'] = Types.get_typelink_and_types_offset['go 1.20']
    Types.get_typename['go 1.21'] = Types.get_typename['go 1.20']
