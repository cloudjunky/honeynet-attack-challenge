__author__ = 'michaelbaker'

import hashlib
import magic
import tempfile
import os
import pefile
import datetime

class FileDissector(object):

    def mime_type(self, buffer):
        try:
            mag = magic.Magic()
            guess = mag.id_buffer(buffer)
            ext = guess.split("/")[-1]
            if ext == 'plain':
                ext = 'txt'
            if ext == 'octet-stream':
                ext = 'exe'
            if ext == 'x-tar':
                ext = 'tar'
            if ext == 'x-shockwave-flash':
                ext = 'swf'
            return guess, ext
        except Exception, e:
            print "Decompression error: {}".format(e)
            return False, False
    @classmethod
    def just_guess(self, buffer):
        try:
            with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as mag:
                guess = mag.id_buffer(buffer)
                return guess
        except Exception, e:
            print e

    @classmethod
    def guess_from_file(self, buffer):
        fp, filename = tempfile.mkstemp(prefix='file')
        payload = buffer
        os.write(fp, payload)
        os.close(fp)
        with magic.Magic() as mag:
            guess = mag.id_filename(filename)
            print "{} -> {} -> {}".format(FileDissector.just_guess(buffer), guess, filename)
            return guess

    @classmethod
    def md5sum(filename, blocksize=65536):
        hash = hashlib.md5()
        with open(filename, "r+b") as f:
            for block in iter(lambda: f.read(blocksize), ""):
                hash.update(block)
        return hash.hexdigest()

    @classmethod
    def is_it_shellcode(self, buffer):
        try:
            import pylibemu
            shellcode = buffer
            emulator = pylibemu.Emulator()
            offset = emulator.shellcode_getpc_test(shellcode)
            if offset >= 0:
                return True, True
            else:
                return False, str(offset)
        except ImportError, e:
            return False, e

    @classmethod
    def show_me_shellcode(self, buffer):
        try:
            import pylibemu
            shellcode = buffer
            emulator = pylibemu.Emulator()
            offset = emulator.shellcode_getpc_test(shellcode)
            emulator.prepare(shellcode, offset)
            emulator.test()
            return emulator.emu_profile_output
        except ImportError, e:
            return False, e

    @classmethod
    def pe_info(self, buffer):
        fp, filename = tempfile.mkstemp(prefix='file')
        payload = buffer
        os.write(fp, payload)
        os.close(fp)
        try:
            pe = pefile.PE(filename)
            print "Optional Header:", hex(pe.OPTIONAL_HEADER.ImageBase)
            print "Address Of Entry Point:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            print "Number of Sections {}".format(len(pe.sections))
            machine = pe.FILE_HEADER.Machine
            print "Required CPU type:", pefile.MACHINE_TYPE[machine]
            if int(pe.is_exe()): print "File is an EXE"
            if int(pe.is_dll()): print "File is a DLL"
            print "Subsystem:", pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem]
            print "Compile Time:", datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            print "Number of RVA and Sizes:", pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            print "Directory Entry Imports: {}".format(len(pe.DIRECTORY_ENTRY_IMPORT))

        except pefile.PEFormatError:
            return False


