## Description
破解CAJViewer加有效期限制的文档，无损转为普通PDF格式文件，保留文字和目录，支持解密以下网站下载的文档：
- 科学文库 ( https://book.sciencereading.cn )
- 国家标准全文数据库 ( https://kns.cnki.net/kns8?dbcode=CISD / https://www.spc.org.cn/ )
- 其他，待验证...

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
## 科学文库无限制下载 
暂不提供，有需要请提issue