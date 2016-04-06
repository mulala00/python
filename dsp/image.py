
"""Module for general DSP stuff."""

import sys
import struct
from ctypes import *
import os
import time


SEC_TYPE_DEF = {
    0: "NULL",
    1: "PROG",
    2: "SYMB",
    3: "TEXT",
    8: ".BSS",
}


def _get_section_type(sh_type):
    if sh_type in SEC_TYPE_DEF:
        return SEC_TYPE_DEF[sh_type]

    return "?%x" % sh_type


def unpack_bin_to_sig(c_type, buf):
    s_string = create_string_buffer(buf)
    return cast(pointer(s_string), POINTER(c_type)).contents


class BasicImageStructure(object):
    _pack_ = 1

    def unpack(self, buf):
        s_string = create_string_buffer(buf)
        return cast(pointer(s_string), POINTER(self.__class__)).contents

    def log_it(self, prefix=""):
        if prefix == "":
            prefix = "%s" % self.__class__.__name__

        for var in self._fields_:
            key = var[0]
            val = getattr(self, key)

            cur_prefix = prefix + "." + key
            if isinstance(val, Array):
                for i in range(len(val)):
                    if isinstance(val[i], Structure) or isinstance(val, Union):
                        val[i].log_it(cur_prefix + "[%d]" % i)
                    else:
                        print "%s[%d] = %s" % (cur_prefix, i, hex(val[i]))

            elif isinstance(val, Structure) or isinstance(val, Union):
                val.log_it(cur_prefix)
            else:
                try:
                    print "%s = %s" % (cur_prefix, hex(val))
                except:
                    print "%s = %s" % (cur_prefix, str(val))


class ElfHeader(BasicImageStructure, BigEndianStructure):
    _fields_ = [
                ("e_ident",     c_char * 16),
                ("e_type",      c_uint16),
                ("e_machine",   c_uint16),
                ("e_version",   c_uint32),
                ("e_entry",     c_uint32),
                ("e_phoff",     c_uint32),
                ("e_shoff",     c_uint32),
                ("e_flags",     c_uint32),
                ("e_ehsize",    c_uint16),
                ("e_phentsize", c_uint16),
                ("e_phnum",     c_uint16),
                ("e_shentsize", c_uint16),
                ("e_shnum",     c_uint16),
                ("e_shstrndx",  c_uint16),
            ]


class ElfSectionHeader(BasicImageStructure, BigEndianStructure):
    _fields_ = [
            ("sh_name",      c_uint32),
            ("sh_type",      c_uint32),   # Section type
            ("flags",     c_uint32),
            ("sh_addr",      c_uint32),   # Section virtual addr at execution
            ("sh_offset",    c_uint32),   # Section file offset
            ("sh_size",      c_uint32),
            ("sh_link",      c_uint32),   # Link to another section
            ("sh_info",      c_uint32),   # Additional section information
            ("sh_addralign", c_uint32),   # Section alignment
            ("sh_entsize",   c_uint32),   # Entry size if section holds table
            ]


# File Header and Section Header define in COFF
class COFFHeader(BasicImageStructure, LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
                ("version",             c_uint16),   #
                ("e_shnum",             c_uint16),   # Number of section
                ("time_and_date",       c_uint32),   # The timestamp of this COFF file
                ("file_ptr",            c_uint32),
                ("num_symbol_entries",  c_uint32),   # Number of symbol
                ("opt_header_size",     c_uint16),   #
                ("flags",               c_uint16),
                ("target",              c_uint16),   # TODO: Not clear
    ]


class COFFSectionHeader(BasicImageStructure, LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
            ("sh_name",                c_char * 8),
            ("sh_addr",                c_uint32),
            ("virtual_address",        c_uint32),
            ("sh_size",                c_uint32),
            ("sh_offset",              c_uint32),   # Section file offset
            ("relocation_entries_ptr", c_uint32),
            ("reserved0",              c_uint32),   # Link to another section
            ("num_relocation_entries", c_uint32),   # Additional section information
            ("reserved1",              c_uint32),   # Section alignment
            ("flags",                  c_uint32),   # 0x20: Text, 0x40: DATA, 0x80:BSS
            ("reserved2",              c_uint16),
            ("memory_page",            c_uint16),
            ]


class Section(object):
    def __init__(self, name, off, addr, size, flags):
        self.name = name
        self.off = off
        self.addr = addr
        self.size = size
        self.flags = flags

    def __str__(self):
        return "%-30s %08X %08X %08X %x" % (self.name, self.off, self.addr, self.size, self.flags)


def is_file_format_elf(path):
    """Checks if the format of given file is ELF."""
    f = open(path, 'rb')
    format_id = f.read(4)
    f.close()
    return _is_elf_format(format_id)


def _is_elf_format(format_id):
    format_id_elf = struct.pack('BBBB', 0x7F, ord('E'), ord('L'), ord('F'))
    if format_id == format_id_elf:
        return True
    else:
        return False


class ImageReader(object):
    def __init__(self, image):
        self.header = None
        self.sections = []
        self.is_elf = False

        if not is_file_format_elf(image):
            self.header_class = COFFHeader
            self.section_class = COFFSectionHeader
        else:
            self.is_elf = True
            self.header_class = ElfHeader
            self.section_class = ElfSectionHeader

        self.image = open(image, "rb")
        self.read_image_header()
        self.read_sections()

    def read_image_header(self):
        raw_header = self.image.read(sizeof(self.header_class))
        self.header = unpack_bin_to_sig(self.header_class, raw_header)
        self.header.log_it()

    def _seek_section_header(self):
        if self.is_elf:
            self.image.seek(self.header.e_shoff, os.SEEK_SET)
        else:
            self.image.seek(self.header.opt_header_size, os.SEEK_CUR)
        print "Come to ", self.image.tell()

    def _read_section_raw(self):
        return self.image.read(sizeof(self.section_class))

    def _read_image_from(self, offset, size):
        self.image.seek(offset, 0)
        return self.image.read(size)

    def _read_string_table(self):
        # The section name store in the section index by 'e_shstrndx' of ELF header
        return self._read_section_content(self.header.e_shstrndx)

    @staticmethod
    def _get_sec_name_by_off(sec_name_tbl, off):
        return sec_name_tbl[off:].split("\0")[0]

    def _read_section_content(self, sec_idx):
        if sec_idx > len(self.sections):
            raise IndexError("List out of range, %d > %d" % (sec_idx, len(self.sections)))
        sec_info = self.sections[sec_idx]
        return self._read_image_from(sec_info.off, sec_info.size)

    def _read_sections(self):
        self._seek_section_header()

        for i in range(self.header.e_shnum):
            sec = unpack_bin_to_sig(self.section_class, self._read_section_raw())
            self.sections.append(Section(sec.sh_name, sec.sh_offset, sec.sh_addr, sec.sh_size, sec.flags))

    def read_sections(self):
        self._read_sections()

        if self.is_elf:
            sec_name_tbl = self._read_string_table()
            for sec in self.sections:
                sec.name = self._get_sec_name_by_off(sec_name_tbl, sec.name)

    def get_section_name_by_addr(self, addr):
        for sec in self.sections:
            if sec.addr == addr:
                return sec.name
        raise IndexError("Address %08x is not a section address" % addr)

    def sanity_test(self):
        for sec in self.sections:
            print sec



if __name__ == '__main__':
    reader = ImageReader(sys.argv[1])
    reader.sanity_test()
