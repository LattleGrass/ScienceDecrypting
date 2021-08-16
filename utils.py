import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
import PyPDF2
from PyPDF2.generic import *


class CustomException(Exception):
    pass


def aes_decrypt(key, iv, data, pad=False):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    ret = dec.update(data) + dec.finalize()
    if not pad:
        return ret
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(ret) + unpadder.finalize()


class MyPdfFileReader(PyPDF2.PdfFileReader):
    def SetFileKey(self, key):
        self._decryption_key = key
        self._override_encryption = False

    def _decrypt(self, password):
        pass

    def getObject(self, indirectReference):
        debug = False
        if debug:
            print(("looking at:", indirectReference.idnum,
                  indirectReference.generation))
        retval = self.cacheGetIndirectObject(indirectReference.generation,
                                             indirectReference.idnum)
        if retval != None:
            return retval
        if indirectReference.generation == 0 and \
                indirectReference.idnum in self.xref_objStm:
            retval = self._getObjectFromStream(indirectReference)
        elif indirectReference.generation in self.xref and \
                indirectReference.idnum in self.xref[indirectReference.generation]:
            start = self.xref[indirectReference.generation][indirectReference.idnum]
            if debug:
                print(("  Uncompressed Object", indirectReference.idnum,
                      indirectReference.generation, ":", start))
            self.stream.seek(start, 0)
            idnum, generation = self.readObjectHeader(self.stream)
            if idnum != indirectReference.idnum and self.xrefIndex:
                # Xref table probably had bad indexes due to not being zero-indexed
                if self.strict:
                    raise utils.PdfReadError("Expected object ID (%d %d) does not match actual (%d %d); xref table not zero-indexed."
                                             % (indirectReference.idnum, indirectReference.generation, idnum, generation))
                else:
                    pass  # xref table is corrected in non-strict mode
            elif idnum != indirectReference.idnum:
                # some other problem
                raise utils.PdfReadError("Expected object ID (%d %d) does not match actual (%d %d)."
                                         % (indirectReference.idnum, indirectReference.generation, idnum, generation))
            assert generation == indirectReference.generation
            retval = readObject(self.stream, self)

            # override encryption is used for the /Encrypt dictionary
            if not self._override_encryption and self.isEncrypted:
                # if we don't have the encryption key:
                if not hasattr(self, '_decryption_key'):
                    raise utils.PdfReadError("file has not been decrypted")
                # otherwise, decrypt here...
                import struct
                pack1 = struct.pack("<i", indirectReference.idnum)[:3]
                pack2 = struct.pack("<i", indirectReference.generation)[:2]
                key = self._decryption_key + pack1 + pack2 + b'sAlT'
                assert len(key) == (len(self._decryption_key) + 9)
                md5_hash = hashlib.md5(key).digest()
                key = md5_hash[:min(16, len(self._decryption_key) + 5)]
                retval = self._decryptObject(retval, key)
        else:
            warnings.warn("Object %d %d not defined." % (indirectReference.idnum,
                                                         indirectReference.generation), utils.PdfReadWarning)
            # if self.strict:
            raise utils.PdfReadError("Could not find object.")
        self.cacheIndirectObject(indirectReference.generation,
                                 indirectReference.idnum, retval)
        return retval

    def _decryptObject(self, obj, key):
        if isinstance(obj, ByteStringObject) or isinstance(obj, TextStringObject):
            obj = createStringObject(aes_decrypt(
                key, obj.original_bytes[:len(key)], obj.original_bytes[len(key):], True))
        elif isinstance(obj, StreamObject):
            obj._data = aes_decrypt(
                key, obj._data[:len(key)], obj._data[len(key):], True)
        elif isinstance(obj, DictionaryObject):
            for dictkey, value in list(obj.items()):
                obj[dictkey] = self._decryptObject(value, key)
        elif isinstance(obj, ArrayObject):
            for i in range(len(obj)):
                obj[i] = self._decryptObject(obj[i], key)
        return obj


def myReadFromStream(stream, pdf):
    debug = False
    tmp = stream.read(2)
    if tmp != b_("<<"):
        raise utils.PdfReadError("Dictionary read error at byte %s: stream must begin with '<<'" % utils.hexStr(stream.tell()))
    data = {}
    while True:
        tok = readNonWhitespace(stream)
        if tok == b_('\x00'):
            continue
        elif tok == b_('%'):
            stream.seek(-1, 1)
            skipOverComment(stream)
            continue
        if not tok:
            # stream has truncated prematurely
            raise PdfStreamError("Stream has ended unexpectedly")

        if debug: print(("Tok:", tok))
        if tok == b_(">"):
            stream.read(1)
            break
        stream.seek(-1, 1)
        key = readObject(stream, pdf)
        tok = readNonWhitespace(stream)
        stream.seek(-1, 1)
        value = readObject(stream, pdf)
        if not data.get(key):
            data[key] = value
        elif pdf.strict:
            # multiple definitions of key not permitted
            raise utils.PdfReadError("Multiple definitions in dictionary at byte %s for key %s" \
                                        % (utils.hexStr(stream.tell()), key))
        else:
            warnings.warn("Multiple definitions in dictionary at byte %s for key %s" \
                                        % (utils.hexStr(stream.tell()), key), utils.PdfReadWarning)

    pos = stream.tell()
    s = readNonWhitespace(stream)
    if s == b_('s') and stream.read(5) == b_('tream'):
        eol = stream.read(1)
        # odd PDF file output has spaces after 'stream' keyword but before EOL.
        # patch provided by Danial Sandler
        while eol == b_(' '):
            eol = stream.read(1)
        assert eol in (b_("\n"), b_("\r"))
        if eol == b_("\r"):
            # read \n after
            if stream.read(1)  != b_('\n'):
                stream.seek(-1, 1)
        # this is a stream object, not a dictionary
        assert "/Length" in data
        length = data["/Length"]
        if debug: print(data)
        stream_start = stream.tell()
        if isinstance(length, IndirectObject):
            length = pdf.getObject(length)
            stream.seek(stream_start, 0)
        data["__streamdata__"] = stream.read(length)
        if debug: print("here")
        #if debug: print(binascii.hexlify(data["__streamdata__"]))
        e = readNonWhitespace(stream)
        ndstream = stream.read(8)
        if (e + ndstream) != b_("endstream"):
            # (sigh) - the odd PDF file has a length that is too long, so
            # we need to read backwards to find the "endstream" ending.
            # ReportLab (unknown version) generates files with this bug,
            # and Python users into PDF files tend to be our audience.
            # we need to do this to correct the streamdata and chop off
            # an extra character.
            pos = stream.tell()
            stream.seek(-10, 1)
            end = stream.read(9)
            if end == b_("endstream"):
                # we found it by looking back one character further.
                data["__streamdata__"] = data["__streamdata__"][:-1]
            else:
                # Handle stream that is few bytes longer than expected
                stream.seek(stream_start + length, 0)
                extra = stream.read(100)
                p = extra.find(b_("endstream"))
                if p >= 0:
                    stream.seek(stream_start + length + p + 9, 0)
                    extra = extra[:p].rstrip(b_('\r\n '))
                    data["__streamdata__"] = data["__streamdata__"] + extra
                else:
                    if debug: print(("E", e, ndstream, debugging.toHex(end)))
                    stream.seek(pos, 0)
                    raise utils.PdfReadError("Unable to find 'endstream' marker after stream at byte %s." % utils.hexStr(stream.tell()))
    else:
        stream.seek(pos, 0)
    if "__streamdata__" in data:
        return StreamObject.initializeFromDictionary(data)
    else:
        retval = DictionaryObject()
        retval.update(data)
        return retval


def patch_pypdf2():
    PyPDF2.PdfFileReader = MyPdfFileReader
    PyPDF2.generic.DictionaryObject.readFromStream = staticmethod(myReadFromStream)
