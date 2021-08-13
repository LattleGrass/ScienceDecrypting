#!/usr/bin/env python3

import base64
import sys
import traceback
import requests
import os
import re
import hashlib
import tempfile
from xml.etree import ElementTree
from optparse import OptionParser
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives import padding
import PyPDF2
from PyPDF2.generic import *

req_data = """<?xml version="1.0" encoding="UTF-8"?>
<auth-req>
<file-id>{}</file-id>
<doi/>
</auth-req>
"""
iv_first = b"200CFC8299B84aa980E945F63D3EF48D"
iv_first = iv_first[:16]


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


def request_password(url, file_id):
    r = requests.post(url, headers={
        "User-Agent": "Readerdex 2.0",
        "Cache-Control": "no-cache"
    }, data=req_data.format(file_id))
    if r.status_code != 200:
        raise CustomException(
            "服务器异常，请稍后再试, file id: {}".format(file_id))
    try:
        root = ElementTree.fromstring(r.text)
    except Exception:
        raise CustomException(
            "invilid response, file id: {}".format(file_id))
    password = root.find("./password").text
    if not password or not password.strip():
        raise CustomException(
            "无法获取密码，文件可能已过期, file id:{}".format(file_id))
    return password.strip()


def decrypt_file_key(password_from_file, password_from_server, iv_from_file, right_meta, rights):
    pass_dec = aes_decrypt(password_from_server, iv_first,
                           base64.b64decode(password_from_file))
    m = hashlib.sha256()
    m.update(pass_dec[:0x20])
    m.update(right_meta)
    sha256 = m.digest()
    iv_second = base64.b64decode(iv_from_file)
    rights_dec = aes_decrypt(sha256, iv_second[:16], base64.b64decode(rights))
    m = re.search(r"<encrypt>([0-9a-f]+)</encrypt>",
                  rights_dec.decode("utf-8"))
    if not m:
        raise CustomException("fail to get encrypt key: {}", rights_dec)
    pass_in_rights = m.group(1)
    pass_in_rights += "AppendCA"
    m = hashlib.sha1()
    m.update(pass_in_rights.encode("utf-8"))
    return m.digest()[:0x10]


def bookmark(outlines, parent, output, input_):
    prev_mark = parent
    for mark in outlines:
        if isinstance(mark, list):
            bookmark(mark, prev_mark, output, input_)
        else:
            mark_number = input_.getDestinationPageNumber(mark)
            prev_mark = output.addBookmark(
                title = mark.title, pagenum = mark_number, parent = parent)

def decrypt_file(src, dest):
    print("[Log] 解析源文件....")
    with open(src, "rb") as fp:
        # find rights position
        fp.seek(0, os.SEEK_END)
        fp.seek(fp.tell() - 30, os.SEEK_SET)
        tail = fp.read()
        m = re.search(r"startrights (\d+),(\d+)", tail.decode("latin"))
        if not m:
            raise CustomException("文件格式错误 {}".format(tail))
        # find rights
        fp.seek(int(m.group(1)), os.SEEK_SET)
        eof_offset = int(m.group(1)) - 13
        right_meta = fp.read(int(m.group(2))).decode("latin")
    # request stage 1 password
    root = ElementTree.fromstring(right_meta)
    drm_url = root.find("./protect/auth/permit/server/url").text
    file_id = root.find("./file-id").text
    password_from_file = root.find("./protect/auth/permit/password").text
    iv_from_file = root.find("./protect/auth/iv").text
    rights = root.find("./rights").text
    stripped_right_meta = re.sub(
        r"\<rights\>[\w+/=]+\</rights\>", "<rights></rights>", right_meta)

    print("[Log] 请求密钥...")
    password_from_server = request_password(drm_url, file_id)

    print("[Log] 解密DRM信息...")
    file_key = decrypt_file_key(password_from_file,
                                password_from_server.encode("ascii"),
                                iv_from_file,
                                stripped_right_meta.encode("ascii"),
                                rights)
    print("[Log] 解密文件...")
    origin_fp = open(src, "rb")
    temp_fp = tempfile.TemporaryFile()
    temp_fp.write(origin_fp.read(eof_offset))
    origin_fp.close()
    temp_fp.seek(0, os.SEEK_SET)

    output = PyPDF2.PdfFileWriter()
    input_ = MyPdfFileReader(temp_fp)
    input_.SetFileKey(file_key)
    input_.strict = False
    print("[Log] 文件 {} 共 {} 页.".format(src, input_.getNumPages()))
    for i in range(input_.getNumPages()):
        print(".", end="", flush=True)
        output.addPage(input_.getPage(i))
    print("\n[Log] 生成目录")
    bookmark(input_.outlines, None, output, input_)
    print("[Log] 写入文件")
    outputStream = open(dest, "wb")
    output.write(outputStream)
    temp_fp.close()
    print("[Success] 解密成功!")


def main():
    parser = OptionParser(
        usage="Usage: python3 %prog -i INPUT_FILE -o OUTPUT_FILE")
    parser.add_option("-i", "--input", dest="src",
                      help="原始文件名", metavar="FILE")
    parser.add_option("-o", "--ouput", dest="dst",
                      help="输出文件名", metavar="FILE")
    (options, _) = parser.parse_args()
    if not options.src or not options.dst:
        parser.print_help()
        exit(0)
    if not os.path.isfile(options.src):
        print("输入文件不存在")
        parser.print_help()
        exit(0)
    if os.path.isfile(options.dst):
        ans = input("文件 {} 已存在，继续运行将覆盖该文件，是否继续 [y/N]: ".format(options.dst))
        if ans.lower() not in ["y", "yes"]:
            exit(0)
    decrypt_file(options.src, options.dst)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Killed by user")
        sys.exit(0)
    except (CustomException, Exception) as exc:
        if not isinstance(exc, CustomException):
            print("[Error] 未知错误: ", str(exc))
        else:
            print("[Error]", str(exc))
        print("\n如果你需要帮助，请复制以下信息到GitHub ( https://github.com/301Moved/ScienceDecrypting/issues/new ) 上提交Issue")
        print("-" * 64)
        traceback.print_exc()
