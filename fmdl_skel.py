#!/usr/bin/env python
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# FMDL sk_prop manipulator
# * adds one bone called "sk_prop" to the model
# * adds bone groups to meshes
# * adds bone weight/bone group info to vertex data
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Author: juce
#
# Most of the information necessary to write this script
# was obtained from the FMDL format wiki:
#   https://metalgearmodding.fandom.com/wiki/FMDL
#
# Whatever few bits of info that were missing in the wiki,
# were figured out by reversing Konami's original FMDLs

import struct
import sys
import copy

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

"""
0x0: Position.
0x1: Bone weights.
0x2: Normals.
0x3: Colour.
0x7: Bone indices.
0x8: Texture UV 0.
0x9: Texture UV 1.
0xA: Texture UV 2.
0xB: Texture UV 3.
0xC: Unknown weights 1.
0xD: Unknown indices 1.
0xE: Tangents.

0x1: Binary32.
0x4: Uint16.
0x6: Binary16.
0x7: Binary16.
0x8: Int8 (normalized).
0x9: Int8.

(Binary16): Normal x.
(Binary16): Normal y.
(Binary16): Normal z.
(Binary16): Normal w.
(Binary16): Tangent x.
(Binary16): Tangent y.
(Binary16): Tangent z.
(Binary16): Tangent w.
(Int8): Colour r.
(Int8): Colour g.
(Int8): Colour b.
(Int8): Colour a.
(Int8): Bone weight 0.
(Int8): Bone weight 1.
(Int8): Bone weight 2.
(Int8): Bone weight 3.
(Int8): Bone id 0.
(Int8): Bone id 1.
(Int8): Bone id 2.
(Int8): Bone id 3.
(Binary16): Texture U 0.
(Binary16): Texture V 0.
(Binary16): Texture U 1.
(Binary16): Texture V 1.
(Binary16): Texture U 2.
(Binary16): Texture V 2.
(Binary16): Texture U 3.
(Binary16): Texture V 3.
(Int8): Unknown weight 0.
(Int8): Unknown weight 1.
(Int8): Unknown weight 2
(Int8): Unknown weight 3.
(Uint16): Unknown index 0.
(Uint16): Unknown index 1.
(Uint16): Unknown index 2.
(Uint16): Unknown index 3.
"""

VERTEX_FORMAT_ORDER = [ 0x02, 0x0e, 0x3, 0x1, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd ]

VERTEX_FORMAT_SIZES = {
    0x2: 8,  # xyzw normal
    0xe: 8,  # xyzw tangent
    0x3: 4,  # rgba color
    0x1: 4,  # 4 bone weights
    0x7: 4,  # 4 bone group ids
    0x8: 4,  # tex0 uv
    0x9: 4,  # tex1 uv
    0xa: 4,  # tex2 uv
    0xb: 4,  # tex3 uv
    0xc: 4,  # unknown weights
    0xd: 16, # unknown indices
}

def vertex_format_key(vf):
    usage = vf['usage']
    for i,v in enumerate(VERTEX_FORMAT_ORDER):
        if v == usage:
            return i
    return -1


def get_block(fmdl, section_id, block_id):
    for block in fmdl['sections'][section_id]['blocks']:
        if block['id'] == block_id:
            return block
    return None


class MeshInfo:
    def __init__(self):
        self.num_vertices = 0
        self.info = {}
        self.mesh_formats = []

    def get_offset_for_chunk(self, chunk_type_id):
        for mf in self.mesh_formats:
            if mf['buffer_offset_id'] == chunk_type_id:
                return mf['offs']
        raise Exception("chunk_type_id not found")

    def get_size_of_entry_for_chunk(self, chunk_type_id):
        for mf in self.mesh_formats:
            if mf['buffer_offset_id'] == chunk_type_id:
                return mf['len']
        raise Exception("chunk_type_id not found")


class ModelInfo:
    def __init__(self, fmdl):
        self.meshes = []
        # process some section 0 blocks
        # 0x3 : mesh info
        block_0x3 = get_block(fmdl, 0, 0x3)

        # 0x9 : mesh format assignments
        block = get_block(fmdl, 0, 0x9)
        if block:
            for i,item in enumerate(block['items']):
                nmf = struct.unpack('<B',item[0:1])[0]
                nvf = struct.unpack('<B',item[1:2])[0]
                unknown = struct.unpack('<H',item[2:4])[0]
                fmf = struct.unpack('<H',item[4:6])[0]
                fvf = struct.unpack('<H',item[6:8])[0]

                num_vertices = struct.unpack('<H', block_0x3['items'][i][0x0a:0x0c])[0]

                mi = MeshInfo()
                mi.num_vertices = num_vertices
                mi.info['num_mesh_formats'] = nmf
                mi.info['num_vertex_formats'] = nvf
                mi.info['unknown'] = unknown
                mi.info['first_mesh_format_id'] = fmf
                mi.info['first_vertex_format_id'] = fvf

                # 0xa : mesh format definitions
                block_0xa = get_block(fmdl, 0, 0xa)
                if block_0xa:
                    j = 0
                    for i in range(fmf, fmf + nmf):
                        item = block_0xa['items'][i]
                        ii = {}
                        ii['buffer_offset_id'] = struct.unpack('<B',item[0:1])[0]
                        ii['num_vertex_formats'] = struct.unpack('<B',item[1:2])[0]
                        ii['len'] = struct.unpack('<B',item[2:3])[0]
                        ii['type'] = struct.unpack('<B',item[3:4])[0]
                        ii['offs'] = struct.unpack('<I',item[4:8])[0]
                        ii['_vf'] = []

                        # 0xb : vertex format definitions
                        block_0xb = get_block(fmdl, 0, 0xb)
                        if block_0xb:
                            for k in range(fvf + j, fvf + j + ii['num_vertex_formats']):
                                item = block_0xb['items'][k]
                                jj = {}
                                jj['usage'] = struct.unpack('<B',item[0:1])[0]
                                jj['type'] = struct.unpack('<B',item[1:2])[0]
                                jj['offs'] = struct.unpack('<H',item[2:4])[0]
                                ii['_vf'].append(jj)
                            #print(ii)
                            j += len(ii['_vf'])

                        mi.mesh_formats.append(ii)

                self.meshes.append(mi)


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

    # some structured info
    fmdl['model_info'] = ModelInfo(fmdl)

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

    # block definitions (incomplete yet: offsets to fill in later)
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


def pad_to(n, align):
    return n + ((align - (n % align)) % align)


def add_padding(data, align):
    rem = (align - (len(data) % align)) % align
    if rem:
        padding = b''.join((b'\x00' for x in range(rem)))
        return b''.join((data, padding))
    return data

def add_sk_prop(fmdl):
    print('Has bones: %s' % has_bones(fmdl))
    print('Has bone groups: %s' % has_bone_groups(fmdl))

    if not has_bone_groups(fmdl):
        num_groups = len(fmdl['model_info'].meshes)
        block = {}
        block['id'] = 0x5
        block['items'] = []
        for i in range(num_groups):
            # add a new bone group def for each mesh
            data = b''.join((
                struct.pack('<H', 1),
                struct.pack('<H', 1),
                b''.join([struct.pack('<H',0) for x in range(0x20)]),
            ))
            block['items'].append(data)
            print('added bone-group for mesh %d' % i)
        fmdl['sections'][0]['blocks'].append(block)

        # adjust mesh info block:
        # set bone group id to mesh ordinal
        block_0x3 = get_block(fmdl, 0, 0x3)
        if block_0x3:
            new_items = []
            for i,item in enumerate(block_0x3['items']):
                new_item = b''.join((
                    item[:0x6],
                    struct.pack('<H', i),
                    item[0x8:],
                ))
                new_items.append(new_item)
            block_0x3['items'] = new_items

        # adjust section flags (important to that: wrong flags - instant crash)
        fmdl['header']['s0_flags'] = fmdl['header']['s0_flags'] | (1 << block['id'])
        print('adjusted section 0 flags')

    if not has_bones(fmdl):
        s0_string_defs = get_block(fmdl, 0, 0xc)
        if not s0_string_defs:
            raise Exception("Problem: no strings definitions block in section 0")

        s1_strings = get_block(fmdl, 1, 0x3)
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
        print('added new bone: %s' % new_str)
        # adjust section flags
        fmdl['header']['s0_flags'] = fmdl['header']['s0_flags'] | (1 << block['id'])
        print('adjusted section 0 flags')

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
        print('added scale/pos matrix block to section 1')
        # adjust section flags
        fmdl['header']['s1_flags'] = fmdl['header']['s1_flags'] | (1 << block['id'])
        print('adjusted section 1 flags')

    mesh_format_blocks = {}
    for block in fmdl['sections'][0]['blocks']:
        if block['id'] in [9,0x0a,0x0b]:
            mesh_format_blocks[block['id']] = block

    # adjust format blocks
    org_info = copy.deepcopy(fmdl['model_info'])
    last_offset = 0

    modified = False
    for mesh in fmdl['model_info'].meshes:
        has_bone_weights = False
        has_bone_group = False
        next_offs = 0
        mf_len = 0

        for mesh_format in mesh.mesh_formats:
            if mesh_format['buffer_offset_id'] == 1:
                next_offs = mesh_format['len']
                for vertex_format in mesh_format['_vf']:
                    usage = vertex_format['usage']
                    if usage == 0x1:
                        has_bone_weights = True
                    elif usage == 0x7:
                        has_bone_group = True

        if has_bone_weights and has_bone_group:
            # nothing to do for this mesh
            last_offset += mesh.num_vertices * next_offs
            last_offset = pad_to(last_offset, 0x10)
            continue

        # add bone_weight and bone_group formats
        # find mesh format of type 3
        mf = None
        for mesh_format in mesh.mesh_formats:
            if mesh_format['buffer_offset_id'] == 1 and mesh_format['type'] == 3:
                mf = mesh_format
                break
        if not mf:
            # add new mesh format
            mf = {
                'buffer_offset_id': 0x01,
                'num_vertex_formats': 0,
                'len': mf_len,
                'type': 0x3,
                'offs': 0, # update later
                '_vf': [],
            }
            mesh.mesh_formats.append(mf)

        if not has_bone_weights:
            mf['num_vertex_formats'] += 1
            mf['_vf'].append({
                'usage': 0x1,
                'type': 0x8,
                'offs': next_offs,
            })
            next_offs = next_offs + VERTEX_FORMAT_SIZES[0x1]
            mf_len = next_offs
        if not has_bone_group:
            mf['num_vertex_formats'] += 1
            mf['_vf'].append({
                'usage': 0x7,
                'type': 0x9,
                'offs': next_offs,
            })
            next_offs = next_offs + VERTEX_FORMAT_SIZES[0x7]
            mf_len = next_offs

        # re-sort the vertex formats
        mf['_vf'].sort(key=vertex_format_key)

        # update offsets in vertex formats
        # for "additional vertex info" chunk
        offs = 0
        for mf in mesh.mesh_formats:
            if mf['buffer_offset_id'] == 1:
                for vf in mf['_vf']:
                    vf['offs'] = offs
                    offs += VERTEX_FORMAT_SIZES[vf['usage']]

        # adjust lengths
        for mesh_format in mesh.mesh_formats:
            if mesh_format['buffer_offset_id'] == 1:
                mesh_format['len'] = mf_len

        # update offsets
        for mesh_format in mesh.mesh_formats:
            if mesh_format['buffer_offset_id'] == 1:
                mesh_format['offs'] = last_offset

        modified = True

        # calculate offset for next mesh
        last_offset += mf_len * mesh.num_vertices
        last_offset = pad_to(last_offset, 0x10)

    if not modified:
        return

    # rebuild block items
    #print('updated blocks ...')
    new_0x9_items = []
    new_0xa_items = []
    new_0xb_items = []

    for i, mi in enumerate(fmdl['model_info'].meshes):
        mfc, vfc = 0, 0
        for mf in mi.mesh_formats:
            mfc += 1
            #print(mf)
            for vf in mf['_vf']:
                vfc += 1
                new_item = b''.join((
                    struct.pack('<B',vf['usage']),
                    struct.pack('<B',vf['type']),
                    struct.pack('<H',vf['offs']),
                ))
                new_0xb_items.append(new_item)

            new_item = b''.join((
                struct.pack('<B',mf['buffer_offset_id']),
                struct.pack('<B',mf['num_vertex_formats']),
                struct.pack('<B',mf['len']),
                struct.pack('<B',mf['type']),
                struct.pack('<I',mf['offs']),
            ))
            new_0xa_items.append(new_item)

        new_item = b''.join((
            struct.pack('<B',mfc),
            struct.pack('<B',vfc),
            struct.pack('<H',mi.info['unknown']),
            struct.pack('<H',i*mfc),
            struct.pack('<H',i*vfc),
        ))
        new_0x9_items.append(new_item)

    block_0x9 = get_block(fmdl, 0, 9)
    block_0x9['items'] = new_0x9_items
    block_0xa = get_block(fmdl, 0, 0xa)
    block_0xa['items'] = new_0xa_items
    block_0xb = get_block(fmdl, 0, 0xb)
    block_0xb['items'] = new_0xb_items

    #for block in fmdl['sections'][0]['blocks']:
    #    if block['id'] in [9,0xa,0xb]:
    #        print(block)

    # adjust vertices in additional vertex chunk
    block_0x0e = get_block(fmdl, 0, 0xe)

    for block in fmdl['sections'][1]['blocks']:
        if block['id'] == 0x02:
            vertices = []

            pos_offs = struct.unpack('<I', block_0x0e['items'][0][8:0xc])[0]
            vdata_offs = struct.unpack('<I', block_0x0e['items'][1][8:0xc])[0]
            faces_offs = struct.unpack('<I', block_0x0e['items'][2][8:0xc])[0]

            scale = 1.0
            pdatas = []
            for mesh in org_info.meshes:
                positions = []
                mpos_offs = pos_offs + mesh.get_offset_for_chunk(0)
                sz = mesh.get_size_of_entry_for_chunk(0)
                for i in range(mesh.num_vertices):
                    x = struct.unpack('<f', block['data'][mpos_offs + sz*i : mpos_offs + sz*i + 4])[0]
                    y = struct.unpack('<f', block['data'][mpos_offs + sz*i + 4: mpos_offs + sz*i + 8])[0]
                    z = struct.unpack('<f', block['data'][mpos_offs + sz*i + 8: mpos_offs + sz*i + 0xc])[0]
                    positions.append((x*scale,y*scale,z*scale))
                pdata = b''.join([
                    b''.join((struct.pack('<f',p[0]), struct.pack('<f',p[1]), struct.pack('<f',p[2])))
                    for p in positions])
                pdata = add_padding(pdata, 0x10)
                pdatas.append(pdata)
            pdata = b''.join(pdatas)

            vdatas = []
            for i,mesh in enumerate(org_info.meshes):
                vertices = []
                mvdata_offs = vdata_offs + mesh.get_offset_for_chunk(1)
                sz = mesh.get_size_of_entry_for_chunk(1)
                # where to insert bone weight and bone groups
                cut_offs = 0
                new_mesh = fmdl['model_info'].meshes[i]
                for mf in new_mesh.mesh_formats:
                    if mf['buffer_offset_id'] == 0x1:  # addition vertex data
                        for vf in mf['_vf']:
                            if vf['usage'] == 0x1:  # bone weight
                                cut_offs = vf['offs']
                                break
                # update vertices
                for i in range(mesh.num_vertices):
                    vertex = block['data'][mvdata_offs + sz*i : mvdata_offs + sz*(i+1)]
                    vertex = b''.join((vertex[:cut_offs], b'\xff\x00\x00\x00', b'\x00\x00\x00\x00',vertex[cut_offs:]))
                    vertices.append(vertex)
                vdata = b''.join(vertices)
                vdata = add_padding(vdata, 0x10)
                vdatas.append(vdata)
            vdata = b''.join(vdatas)

            faces = block['data'][faces_offs:]
            block['data'] = b''.join((pdata, vdata, faces))

            pdata_len = len(pdata)
            vdata_offs = pos_offs + pdata_len
            vdata_len = len(vdata)
            faces_offs = vdata_offs + vdata_len

            item0 = block_0x0e['items'][0]
            item0 = item0[:4] + struct.pack('<I', pdata_len) + struct.pack('<I', pos_offs) + item0[0xc:]
            item1 = block_0x0e['items'][1]
            item1 = item1[:4] + struct.pack('<I', vdata_len) + struct.pack('<I', vdata_offs) + item1[0xc:]
            item2 = block_0x0e['items'][2]
            item2 = item2[:8] + struct.pack('<I', faces_offs) + item2[0xc:]
            block_0x0e['items'] = [item0, item1, item2]
            #print(block_0x0e['items'])
            print('additional vertex data chunk updated')


if __name__ == "__main__":
    if len(sys.argv)<3:
        print('Usage: %s <input.fmdl> <output.fmdl>' % sys.argv[0])
        sys.exit(0)

    with open(sys.argv[1],"rb") as f:
        fmdl = read_fmdl(f)

    add_sk_prop(fmdl)

    with open(sys.argv[2],"w+b") as f:
        write_fmdl(f, fmdl)

