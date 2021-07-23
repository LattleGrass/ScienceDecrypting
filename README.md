## Description
破解科学文库下载的PDF文件，转为正常的PDF文件格式，去除文件有效期限制，普通PDF阅读器也可以打开。

## Requirements
### Python3
https://www.python.org/downloads/ 下载安装Python3
### PyPDF2/requests/...
执行以下命令安装依赖
```bash
pip3 install -U pip
pip3 install -r requirements.txt
```
## Usage
```
Usage: python3 decrypt.py -i INPUT_FILE -o OUTPUT_FILE

Options:
  -h, --help            show this help message and exit
  -i FILE, --input=FILE  原始文件名
  -o FILE, --ouput=FILE  输出文件名

Example: python3 decrypt.py -i test.pdf -o test_dec.pdf
```