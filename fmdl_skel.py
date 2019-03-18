# FMDL sk_prop manipulator
# ~~~~~~~~~~~~~~~~~~~~~~~~

import struct
import sys

"""
0x0: Bone definitions.
0x1: Mesh group definitions.
0x2: Mesh group assignments.
0x3: Mesh information.
0x4: Material instance definitions.
0x5: Bone group definitions.
0x6: Texture definitions.
0x7: Texture type/material parameter assignments.
0x8: Material/material type assignments.
0x9: Mesh format assignments.
0xA: Mesh format definitions.
0xB: Vertex format definitions.
0xC: String definitions.
0xD: Bounding box definitions.
0xE: Buffer offsets.
0x10: LOD Information.
0x11: Face index definitions.
0x12: Unknown.
0x14: Unknown.
0x15: Texture path hash definitions.
0x16: String hash definitions.
"""

BLOCK_TYPES = {
    0    : { 'name': 'bone_def', 'len': 0x30 },
    1    : { 'name': 'mesh_group_def', 'len': 8 },
    2    : { 'name': 'mesh_group_assign', 'len': 0x20 },
    3    : { 'name': 'mesh_info', 'len': 0x30 },
    4    : { 'name': 'material_instance_def', 'len': 0x10 },
    5    : { 'name': 'bone_group', 'len': 0x44 },
    6    : { 'name': 'tex_def', 'len': 0x4 },
    7    : { 'name': 'tex_type_material_assign', 'len': 0x4 },
    8    : { 'name': 'material_type_assign', 'len': 0x4 },
    9    : { 'name': 'mesh_format_assign', 'len': 0x8 },
    0xa  : { 'name': 'mesh_format_def', 'len': 0x8 },
    0xb  : { 'name': 'vertex_format_def', 'len': 0x4 },
    0xc  : { 'name': 'string_def', 'len': 0x8 },
    0xd  : { 'name': 'bounding_box_def', 'len': 0x20 },
    0xe  : { 'name': 'bounding_box_def', 'len': 0x10 },
    0x10 : { 'name': 'lod_info', 'len': 0x10 },
    0x11 : { 'name': 'face_index_def', 'len': 0x8 },
    0x12 : { 'name': 'unknown', 'len': 0x8 },
    0x14 : { 'name': 'unknown', 'len': 0x80 },
    0x15 : { 'name': 'tex_path_hash_def', 'len': 0x8 },
    0x16 : { 'name': 'string_hash_def', 'len': 0x8 },
}


def read_block(f, block_id):
    block_type = BLOCK_TYPES[block_id] 
    data = f.read(block_type['len'])
    return data
    

def read_fmdl(f):
    fmdl = {
        'header': None,
        'sections': [],
    }
    f.seek(0)

    # header
    fmdl['header'] = {}
    fmdl['header']['magic'] = f.read(4)
    fmdl['header']['version'] = struct.unpack('<f', f.read(4))[0]
    blocks_offs = struct.unpack('<Q', f.read(8))[0]
    fmdl['header']['s0_flags'] = struct.unpack('<Q', f.read(8))[0]
    fmdl['header']['s1_flags'] = struct.unpack('<Q', f.read(8))[0]

    num_s0_blocks = struct.unpack('<I', f.read(4))[0]
    num_s1_blocks = struct.unpack('<I', f.read(4))[0]

    s = [ {}, {} ]
    s[0]['offs'] = struct.unpack('<I', f.read(4))[0]
    s[0]['len'] = struct.unpack('<I', f.read(4))[0]
    s[1]['offs'] = struct.unpack('<I', f.read(4))[0]
    s[1]['len'] = struct.unpack('<I', f.read(4))[0]
    
    # blocks defs
    f.seek(blocks_offs)
    fmdl['sections'] = [
        { 'blocks': [] },
        { 'blocks': [] },
    ]
    for i in range(num_s0_blocks):
        block = {}
        block['id'] = struct.unpack('<H', f.read(2))[0]
        block['num_items'] = struct.unpack('<H', f.read(2))[0]
        block['offs'] = struct.unpack('<I', f.read(4))[0]
        fmdl['sections'][0]['blocks'].append(block)
    for i in range(num_s1_blocks):
        block = {}
        block['id'] = struct.unpack('<I', f.read(4))[0]
        block['offs'] = struct.unpack('<I', f.read(4))[0]
        block['len'] = struct.unpack('<I', f.read(4))[0]
        fmdl['sections'][1]['blocks'].append(block)

    # read the blocks data
    section = s[0]
    for block in fmdl['sections'][0]['blocks']:
        f.seek(section['offs'] + block['offs'])
        block['items'] = []
        for k in range(block['num_items']):
            block['items'].append(read_block(f, block['id']))
        del block['num_items']

    section = s[1]
    for block in fmdl['sections'][1]['blocks']:
        f.seek(section['offs'] + block['offs'])
        block['data'] = f.read(block['len'])
             
    return fmdl


def block_key(b):
    return b['id']


def has_bones(fmdl):
    for block in fmdl['sections'][0]['blocks']:
        if block['id'] == 0x0:
            return True
    return False


def has_bone_groups(fmdl):
    for block in fmdl['sections'][0]['blocks']:
        if block['id'] == 0x5:
            return True
    return False


def has_scale_pos_matrix(fmdl):
    for block in fmdl['sections'][1]['blocks']:
        if block['id'] == 0x1:
            return True
    return False


def write_padding(f, align):
    curr_offs = f.tell()
    padding_len = (align - (curr_offs % align)) % align 
    for i in range(padding_len):
        f.write('\0'.encode('utf-8'))


def write_fmdl(f, fmdl):
    f.seek(0)

    # header
    f.write(fmdl['header']['magic'])
    f.write(struct.pack('<f', fmdl['header']['version']))
    f.write(struct.pack('<Q', 0x40))
    f.write(struct.pack('<Q', fmdl['header']['s0_flags']))
    f.write(struct.pack('<Q', fmdl['header']['s1_flags']))
    f.write(struct.pack('<I', len(fmdl['sections'][0]['blocks'])))
    f.write(struct.pack('<I', len(fmdl['sections'][1]['blocks'])))
    s0_info_loc = f.tell()
    f.write(struct.pack('<I', 0))
    f.write(struct.pack('<I', 0))
    s1_info_loc = f.tell()
    f.write(struct.pack('<I', 0))
    f.write(struct.pack('<I', 0))
    # padding
    write_padding(f, 0x10)

    # sort section blocks by id
    fmdl['sections'][0]['blocks'].sort(key=block_key)
    fmdl['sections'][1]['blocks'].sort(key=block_key)

    # block definitions (incomplete)
    f.seek(0x40)
    s0_blocks_info_loc = f.tell()
    for block in fmdl['sections'][0]['blocks']:
        f.write(struct.pack('<H', block['id']))
        f.write(struct.pack('<H', len(block['items'])))
        f.write(struct.pack('<I', 0))  # offset: tbd
    s1_blocks_info_loc = f.tell()
    for block in fmdl['sections'][1]['blocks']:
        f.write(struct.pack('<I', block['id']))
        f.write(struct.pack('<I', 0))  # offset: tbd
        f.write(struct.pack('<I', len(block['data'])))
    write_padding(f, 0x10)

    # section 0 blocks
    s0_offs = f.tell()
    for block in fmdl['sections'][0]['blocks']:
        block['offs'] = f.tell() - s0_offs
        for item in block['items']:
            f.write(item)
        if block['id'] == 0x0c:
            write_padding(f, 0x10)
    write_padding(f, 0x10)
    s0_len = f.tell() - s0_offs
    
    # section 1 blocks
    s1_offs = f.tell()
    for block in fmdl['sections'][1]['blocks']:
        block['offs'] = f.tell() - s1_offs
        f.write(block['data'])
    s1_len = f.tell() - s1_offs

    # update offsets
    f.seek(s0_info_loc)
    f.write(struct.pack('<I', s0_offs))
    f.write(struct.pack('<I', s0_len))
    f.seek(s1_info_loc)
    f.write(struct.pack('<I', s1_offs))
    f.write(struct.pack('<I', s1_len))

    f.seek(s0_blocks_info_loc)
    for block in fmdl['sections'][0]['blocks']:
        f.write(struct.pack('<H', block['id']))
        f.write(struct.pack('<H', len(block['items'])))
        f.write(struct.pack('<I', block['offs']))
    f.seek(s1_blocks_info_loc)
    for block in fmdl['sections'][1]['blocks']:
        f.write(struct.pack('<I', block['id']))
        f.write(struct.pack('<I', block['offs']))
        f.write(struct.pack('<I', len(block['data'])))


def get_next_string_id(fmdl):
    for block in fmdl['sections'][0]['blocks']:
        if block['id'] == 0x0c:
            return len(block['items'])
    return 0


with open(sys.argv[1],"rb") as f:
    fmdl = read_fmdl(f)

print(has_bones(fmdl))
print(has_bone_groups(fmdl))

with open("test.fmdl","w+b") as f:
    write_fmdl(f, fmdl)

if not has_bone_groups(fmdl):
    # add new bone group def
    data = b''.join((
        struct.pack('<H', 1),
        struct.pack('<H', 1),
        b''.join([struct.pack('<H',0) for x in range(0x20)]),
    ))
    block = {}
    block['id'] = 0x5
    block['items'] = []
    block['items'].append(data)
    fmdl['sections'][0]['blocks'].append(block)
    # adjust section flags
    fmdl['header']['s0_flags'] = fmdl['header']['s0_flags'] | (1 << block['id'])

if not has_bones(fmdl):
    s0_string_defs = None
    for block in fmdl['sections'][0]['blocks']:
        if block['id'] == 0x0c:
            s0_string_defs = block
            break
    if not s0_string_defs:
        raise Exception("Problem: no strings definitions block in section 0")

    s1_strings = None
    for block in fmdl['sections'][1]['blocks']:
        if block['id'] == 0x03:
            s1_strings = block
            break
    if not s1_strings:
        raise Exception("Problem: no strings block in section 1")

    # all strings
    strs = []
    for sdef in s0_string_defs['items']:
        s_len = struct.unpack('<H', sdef[2:4])[0]
        s_offs = struct.unpack('<I', sdef[4:8])[0]
        strs.append(s1_strings['data'][s_offs:s_offs + s_len])

    # rebuild s1 strings data
    s1_strings['data'] = b''.join([b''.join((x, b'\0')) for x in strs])
    new_str_offs = len(s1_strings['data'])
    
    # add new string: "sk_prop"
    new_str = "sk_prop"
    string_id = len(strs)
    strs.append(new_str.encode('utf-8'))
    s1_strings['data'] = b''.join([b''.join((x, b'\0')) for x in strs])

    item = b''.join((
        struct.pack('<H', 0x03),
        struct.pack('<H', len(new_str)),
        struct.pack('<I', new_str_offs),
    ))
    s0_string_defs['items'].append(item)

    # add new bone def
    data = b''.join((
        struct.pack('<H', string_id),
        struct.pack('<H', 0xffff),
        struct.pack('<H', 0),  # bounding box id
        struct.pack('<H', 1),  # unknown
        struct.pack('<Q', 0),  # padding
        # local position
        struct.pack('<f', 0),
        struct.pack('<f', 0),
        struct.pack('<f', 0),
        struct.pack('<f', 1.0),
        # world position
        struct.pack('<f', 0),
        struct.pack('<f', 0),
        struct.pack('<f', 0),
        struct.pack('<f', 1.0),
    ))
    block = {}
    block['id'] = 0x0
    block['items'] = []
    block['items'].append(data)
    fmdl['sections'][0]['blocks'].append(block)
    # adjust section flags
    fmdl['header']['s0_flags'] = fmdl['header']['s0_flags'] | (1 << block['id'])

if not has_scale_pos_matrix(fmdl):
    data = b''.join((
        struct.pack('<f', 1.0), struct.pack('<f', 0.0), struct.pack('<f', 0.0), struct.pack('<f', 0.0),
        struct.pack('<f', 0.0), struct.pack('<f', 1.0), struct.pack('<f', 0.0), struct.pack('<f', 0.0),
        struct.pack('<f', 0.0), struct.pack('<f', 0.0), struct.pack('<f', 1.0), struct.pack('<f', 0.0),
        struct.pack('<f', -0.0), struct.pack('<f', -0.0), struct.pack('<f', -0.0), struct.pack('<f', 1.0),
    ))
    block = {}
    block['id'] = 0x01
    block['data'] = data
    fmdl['sections'][1]['blocks'].append(block)
    # adjust section flags
    fmdl['header']['s1_flags'] = fmdl['header']['s1_flags'] | (1 << block['id'])

mesh_format_blocks = {}
for block in fmdl['sections'][0]['blocks']:
    if block['id'] in [9,0x0a,0x0b]:
        mesh_format_blocks[block['id']] = block

# adjust format blocks
block = mesh_format_blocks.get(0x0b)
if block:
    block['items'].append(b'\x01\x08\x14\x00')  # bone weight
    block['items'].append(b'\x07\x09\x18\x00')  # bone group

org_vlen = 0
vlen = 0

block = mesh_format_blocks.get(0x0a)
if block and block['items']:
    new_items = []
    for item in block['items']:
        if item[0] == 1:
            # format spec for additional vertex chunk
            org_vlen = struct.unpack('<B',item[2:3])[0]
            vlen = org_vlen + 8
            new_item = b''.join((item[:2], struct.pack('<B', vlen), item[3:]))
            new_items.append(new_item)
        else:
            new_items.append(item)
    block['items'] = new_items
    if vlen > 0:
        block['items'].append(
            b'\x01\x02' + struct.pack('<B', vlen) + b'\x03\x00\x00\x00\x00')
    
block = mesh_format_blocks.get(0x09)
if block:
    block_0xa = mesh_format_blocks.get(0x0a)
    block_0xb = mesh_format_blocks.get(0x0b)
    if block_0xa and block_0xb:
        block['items'] = [b''.join((
            struct.pack('<B', len(block_0xa['items'])),
            struct.pack('<B', len(block_0xb['items'])),
            b'\x00\x01',
            b'\x00\x00\x00\x00',
        ))]

for block in fmdl['sections'][0]['blocks']:
    if block['id'] in [9,0xa,0xb]:
        print(block)


def add_padding(data, align):
    rem = (0x10 - len(data) % 0x10) % 0x10
    if rem:
        padding = b''.join(('\x00' for x in range(rem)))
        return b''.join((data, padding))
    return data


# adjust vertices in additional vertex chunk
num_vertices = 0
for block in fmdl['sections'][0]['blocks']:
    if block['id'] == 0x03:
        for item in block['items']:
            num_vertices += struct.unpack('<H', item[0x0a:0x0c])[0]

block_0x0e = None
for block in fmdl['sections'][0]['blocks']:
    if block['id'] == 0x0e:
        block_0x0e = block

for block in fmdl['sections'][1]['blocks']:
    if block['id'] == 0x02:
        vertices = []

        vdata_offs = struct.unpack('<I', block_0x0e['items'][1][8:0xc])[0]
        faces_offs = struct.unpack('<I', block_0x0e['items'][2][8:0xc])[0]
        
        positions = block['data'][:vdata_offs]
        faces = block['data'][faces_offs:]

        for i in range(num_vertices): 
            vertex = block['data'][vdata_offs + org_vlen*i : vdata_offs + org_vlen*(i+1)]
            vertex = b''.join((vertex, b'\xff\x00\x00\x00',b'\x00\x00\x00\x00'))
            vertices.append(vertex)
        vdata = b''.join(vertices)
        vdata = add_padding(vdata, 0x10)

        block['data'] = b''.join((positions, vdata, faces))

        vdata_len = len(vdata)
        faces_offs = vdata_offs + vdata_len

        print(block_0x0e['items'])
        item1 = block_0x0e['items'][1] 
        item1 = item1[:4] + struct.pack('<I', vdata_len) + item1[8:]
        item2 = block_0x0e['items'][2] 
        item2 = item2[:8] + struct.pack('<I', faces_offs) + item2[0xc:]
        block_0x0e['items'] = [block_0x0e['items'][0], item1, item2]
        print(block_0x0e['items'])

    
with open("test1.fmdl","w+b") as f:
    write_fmdl(f, fmdl)


