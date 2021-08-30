import sys
import traceback
import threading
import tkinter as tk
from tkinter.filedialog import askopenfile

from decrypt import decrypt_file, CustomException


class StdoutRedirector(object):
    def __init__(self, text_widget):
        self.text_space = text_widget

    def write(self, string):
        self.text_space.insert('end', string)
        self.text_space.see('end')


def open_file():
    file = askopenfile(filetypes=[
        ("PDF/CAJ Files", "*")])
    if not file:
        return
    src = file.name
    dst_array = src.split(".")[:-1]
    dst_array.append("dec")
    dst_array.append("pdf")
    dst = ".".join(dst_array)
    print("开始解密", src)
    threading.Thread(target=decrypt_background, args=(src, dst)).start()


def decrypt_background(src, dst):
    try:
        decrypt_file(src, dst)
        print("解密成功！解密后的文件为：", dst)
    except Exception as exc:
        if not isinstance(exc, CustomException):
            print("[Error] 解密失败，未知错误: ", str(exc))
        else:
            print("[Error] 解密失败，", str(exc))
        print("\n如果你需要帮助，请复制以下信息到GitHub ( https://github.com/301Moved/ScienceDecrypting/issues/new ) 上提交Issue")
        print("-" * 64)
        traceback.print_exc()


if __name__ == "__main__":
    root = tk.Tk()
    root.title("ScienceDecrypting")
    root.geometry("800x600")
    btn = tk.Button(root, text='选择要解密的文件', command=lambda: open_file())
    btn.pack(side=tk.TOP, pady=20)
    LOG = tk.Text(root)
    LOG.pack()
    sys.stdout = StdoutRedirector(LOG)
    sys.stderr = StdoutRedirector(LOG)
    tk.mainloop()
