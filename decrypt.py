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
from utils import CustomException, aes_decrypt, patch_pypdf2
import PyPDF2

req_data = """<?xml version="1.0" encoding="UTF-8"?>
<auth-req>
<file-id>{}</file-id>
<doi/>
</auth-req>
"""
iv_first = b"200CFC8299B84aa980E945F63D3EF48D"
iv_first = iv_first[:16]


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
    input_ = PyPDF2.PdfFileReader(temp_fp)
    input_.SetFileKey(file_key)
    input_.strict = False
    print("[Log] 文件 {} 共 {} 页.".format(src, input_.getNumPages()))
    output.cloneReaderDocumentRoot(input_)
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
    # patch PyPDF2 to support aes encryption and fix some bug
    patch_pypdf2()
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
