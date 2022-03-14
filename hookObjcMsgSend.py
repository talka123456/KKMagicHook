import os
import re
import struct
from pathlib import Path

'''
静态库结构

1、魔数 8个字节
magic(8) = '!<arch>\n'

2、符号表头结构 80个字节
struct symtab_header {
    char        name[16];       /* 名称 */
    char        timestamp[12];  /* 库创建的时间戳 */
    char        userid[6];        /* 用户id */
    char        groupid[6];  /* 组id */
    uint64_t    mode;            /* 文件访问模式 */
    uint64_t    size;            /* 符号表占总字节大小 实际指的是符号表 + 符号表长名 的大小*/
    uint32_t    endheader;        /* 头结束标志 */
    char        longname[20];   /* 符号表长名 */
};

3、符号表 4+size个字节
struct symbol_table {
    uint32_t       size;           /* 符号表占用的总字节数 */
    symbol_info syminfo[0];      /* 符号信息，它的个数是 size / sizeof(symbol_info) */
};

3、字符串表 4+size个字节
struct stringtab
{
    int size;     //字符串表的尺寸
    char strings[0];   //字符串表的内容，每个字符串以\0分隔。
};

4、目标文件头结构（跟符号表头结构一样） 80个字节

struct object_header {
    char        name[16];       /* 名称 */
    char        timestamp[12];  /* 目标文件创建的时间戳 */
    char        userid[6];        /* 用户id */
    char        groupid[6];  /* 组id */
    uint64_t    mode;            /* 文件访问模式 */
    uint64_t    size;            /* 符号表占总字节大小 */
    uint32_t    endheader;        /* 头结束标志 */
    char        longname[20];   /* 符号表长名 */
};

5、目标文件
这个可以参考我的博客：https://juejin.im/post/5d5275b251882505417927b5

.....4、5循环（如果有多个目标文件）

'''

'''
处理通用二进制文件， 又称为胖二进制文件

'''
def deal_fat_file():
    global staticLibPath, fatFilePath
    fatFilePath = staticLibPath
    # 路径拆分为目录+文件
    (fatFileDir, fatFileName) = os.path.split(fatFilePath)
    fatFileName = 'tmp-arm64-'+fatFileName
    # 临时 arm64 架构 matcho
    staticLibPath = os.path.join(fatFileDir, fatFileName)
    # 通过 lipo 工具拆分 arm64 架构
    os.system('lipo ' + fatFilePath + ' -thin ' + 'arm64 -output '+ staticLibPath)

# 替换掉通用二进制文件中的 arm64 架构包为新的，
def replace_fat_file():
    os.system('lipo '+fatFilePath+' -replace arm64 '+staticLibPath+' -output '+fatFilePath)
    os.remove(staticLibPath)
    
# 校验路径合法性， 是否为通用二进制包， 是否包含 arm64架构 以及 文件起始的 8 字节带下的 magic 魔数是否合法
def get_valid_staticLib_path():
    if not Path(staticLibPath).is_file():
        return False, 'invalid path, please input valid staticLib path!!!'
    output = os.popen('lipo -info '+staticLibPath).read().strip()
    if not output.endswith('architecture: arm64'):  # re.match(r'.*architecture: arm64$', output):
        if output.startswith('Architectures in the fat file:') and output.find('arm64'):
            deal_fat_file()
        else:
            return False, 'invalid staticLib or fat file not contain arm64 lib'
    with open(staticLibPath, 'rb') as fileobj:
        magic = fileobj.read(8)
        (magic,) = struct.unpack('8s', magic)
        magic = magic.decode('utf-8')
        if not magic == '!<arch>\n':
            return False, 'error magic, invalid staticLib.'
    return True, 'valid path!'


# 返回(name, location, size)
'''
offset: 当前字节偏移量

2、符号表头结构 80个字节
struct symtab_header {
    char        name[16];       /* 名称 16字节 */
    char        timestamp[12];  /* 库创建的时间戳 12 字节 */
    char        userid[6];        /* 用户id 6 字节 */
    char        groupid[6];  /* 组id 6 字节 */
    uint64_t    mode;            /* 文件访问模式 8 字节 */
    uint64_t    size;            /* 符号表占总字节大小 8 字节 */
    uint32_t    endheader;        /* 头结束标志 4 字节*/
    char        longname[20];   /* 符号表名 20字节 */
};

- python 中的struct主要是用来处理C结构数据的，读入时先转换为Python的 字符串 类型，然后再转换为Python的结构化类型，比如元组(tuple)啥的~。一般输入的渠道来源于文件或者网络的二进制流。
关于 python 和 c 数据结构的转换可以查看 [struct.pack()和struct.unpack() 详解（](https://www.cnblogs.com/YuanShiRenY/p/Python_Pack_Unpack.html)
16s: 16表示字节长度， s 表示类型为 char[] 即字符串

- uint64_t: 8 字节长度大小，扩展： uint32_t： 4 字节无符号整数； uint16_t： 2 字节无符号整数；uintptr_t：大小等于指针的无符号整数（64位上一般为 8字节）

- location:参数定义为header 结尾的位置,即数据开始的位置。
'''
def resolver_object_header(offset):
    # 开始解析 arm64 lib
    with open(staticLibPath, 'rb') as fileobj:
        # 定位到偏移处
        fileobj.seek(offset)
        # 读取 16 字节是目标文件的 name，解码
        name = fileobj.read(16)
        (name,) = struct.unpack('16s', name)
        name = name.decode()
        
        # offset(48+offset) = offset + name(16) + timestamp(12) + userid(6) + groupid(6) + mode(8)
        fileobj.seek(48+offset)
        # 读取 8 字节获取 size
        size = fileobj.read(8)
        (size,) = struct.unpack('8s', size)
        size = int(size.decode())
        
        # offset(60+offset) = offset + name(16) + timestamp(12) + userid(6) + groupid(6) + mode(8) + size(8) + endheader(4)
        location = 60 + offset
        
        # 如果 name 是'#1/xxx'开头表示, 则表示 name 实际存储在longname中 长度为 xxx 大小
        if name.startswith('#1/'):
            nameLen = int(name[3:])
            # size 实际包含的是.o 大小以及 logname[] 的大小, 所以实际符号表大小要减去logname[]
            size = size - nameLen
            # 重新定位符号表的起始位置
            location = location + nameLen
            
            # 重新从 longname 中读取字符串
            fileobj.seek(60+offset)
            name = fileobj.read(nameLen)
            (name,) = struct.unpack(str(nameLen)+'s', name)
            name = name.decode().strip()
    return (name, location, size)

'''
查找符号表， 方法就是通过遍历 Load Commands 一次匹配 Segment 的名称，
需要了解 LC_SEGMENGT_64 结构体， 这里只涉及到前两个变量，command (名称定义值)和 command size（lc 大小）
LC_SEGMENGT_64 {

}

这里为什么要收集所有目标文件中的被 hook 符号，原因在于静态库头部的符号和字符串表是一个并集， 目的是加快链接速度， 实际上每一个目标文件在链接时，查找的是自身 MachO 中的符号和字符串表，所以需要收集所有需要修改的位置。而不是单纯的改静态库头部的符号表和字符串表。
'''
def find_symtab(location, size):
    with open(staticLibPath, 'rb') as fileobj:
    # 定位到数据开始的位置，
        fileobj.seek(location)
        # 读取 MachO 结构的前四个字节， 表示魔数
        magic = fileobj.read(4)
        (magic,) = struct.unpack('I', magic)
        # arm64 mach-o magic
        if not magic == 0xFEEDFACF:
            exit('静态库里的machO文件不是arm64平台的！')
            
        # 定位到 load command 数量位置读取四字节，是 lc 数目的条数
        fileobj.seek(location+16)
        num_command = fileobj.read(4)
        (num_command,) = struct.unpack('I', num_command)
        # offset 偏移到 Load Command 的数据位置
        offset = location+32
        while num_command > 0:
            fileobj.seek(offset)
            # cmd 名称
            cmd = fileobj.read(4)
            (cmd,) = struct.unpack('I', cmd)
            if cmd == 0x2: # LC_SYMTAB = 0x2
            # 定位到 string table offset
                offset = offset + 16
                fileobj.seek(offset)
                # 读取偏移值
                stroff = fileobj.read(4)
                (stroff,) = struct.unpack('I', stroff)
                # 读取字符串表大小
                strsize = fileobj.read(4)
                (strsize,) = struct.unpack('I', strsize)
                # 添加到 symtabList_loc_size 中， 格式为（offset, size）
                symtabList_loc_size.append((stroff+location, strsize))
                break
            # 读取 lc 占用大小
            cmd_size = fileobj.read(4)
            (cmd_size,) = struct.unpack('I', cmd_size)
            # 计算下一条 lc 偏移位置
            offset = offset + cmd_size


# 替换读取到的数据， 这里替换的方式是从头读取静态库二进制，如果是匹配到的位置，则替换为新的二进制数据， 否则读取原来库中的数据，拼接成完整的二进制数据流
# 所以入参为 fileLen， 目的就是从头到尾重新拼接二进制流
def replace_Objc_MsgSend(fileLen):
    print('开始替换objc_msgSend...(静态库很大的话，可能需要等十几秒)!!!')
    pos = 0
    bytes = b''
    (loc, size) = symtabList_loc_size[0]
    listIndex = 1
    with open(staticLibPath, 'rb') as fileobj:
        while pos < fileLen:
        # 匹配到需要修改符号的位置，
            if pos == loc:
            # 读取原来的 _objc_msgSend后替换为hook_msgSend
                content = fileobj.read(size)
                content = content.replace(b'\x00_objc_msgSend\x00', b'\x00_hook_msgSend\x00')
                # 重新更新定位
                pos = pos + size
                if listIndex < len(symtabList_loc_size):
                    (loc, size) = symtabList_loc_size[listIndex]
                    listIndex = 1 + listIndex
            else:
            # 默认步进为 4 字节
                step = 4
                # 如果当前需要修改符号定位 > position, 则步进到 loc 位置
                if loc > pos:
                    step = loc - pos
                else:
                    step = fileLen - pos
                    
                    # 读取二进制数据
                content = fileobj.read(step)
                
                # 更新position
                pos = pos + step
                # 拼接
            bytes = bytes + content
            
    with open(staticLibPath, 'wb+') as fileobj:
        print('开始写入文件...')
        fileobj.write(bytes)
        
    if len(fatFilePath) > 0:
    # 将 arm64 修改后的静态库文件替换旧的 arm64 架构
        replace_fat_file()

    print('处理完了！！！')


# 预处理类集合逻辑， 是否全部 hook 还是单独 hook 部分类， 最终都是通过 find_symtab 查找符号表。
need_process_objFile = set() # set('xx1', 'xx2') 表示静态库中，仅xx1跟xx2需要处理
needless_process_objFile = set() # set('xx1', 'xx2') 表示静态库中，xx1跟xx2不需要处理，剩下的都需要处理

def process_object_file(name, location, size):
    # 根据需要，下面三行中，只需打开一行，另外两行需要注释掉
    process_mode = 'default' # 默认处理该静态库中的所有目标文件(类)
    #process_mode = 'need_process_objFile' # 只处理need_process_objFile集合(上面的集合，需要赋值)中的类
    #process_mode = 'needless_process_objFile' # 除了needless_process_objFile集合(上面的集合，需要赋值)中的类不处理，剩下的都需要处理

    # 这里可以过滤不需要处理的目标文件，或者只选择需要处理的目标文件
    # 默认处理该静态库中的所有目标文件
    if process_mode == 'need_process_objFile':
        if name in need_process_objFile:
            find_symtab(location, size)
    elif process_mode == 'needless_process_objFile':
        if not name in need_process_objFile:
            find_symtab(location, size)
    else:
        find_symtab(location, size)
    



# 静态库的路径
staticLibPath = '完整的静态库路径'
fatFilePath = str()
# objc_msgSend被替换的名字（两者长度需一致）
# hookObjcMsgSend-arm64.s里定义了函数名为hook_msgSend，如果修改脚本里的函数名，hookObjcMsgSend-arm64.s里的函数名，也需跟脚本保持一致
# 建议不修改hook_msgSend
hook_msgSend_method_name = 'hook_msgSend'
symtabList_loc_size = list()


if __name__ == '__main__':
    # staticLibPath = '/Users/xx/xx/xx'.strip()
    staticLibPath = input('请输入静态库的路径：').strip()

    if not len(hook_msgSend_method_name) == len('objc_msgSend'):
        exit('need len(\'hook_msgSend\') == len(\'objc_msgSend\')!')
        
    # 校验路径是否合法
    isValid, desc = get_valid_staticLib_path()
    if not isValid:
        exit(desc)
        
    # 找到每个目标文件里的字符串表location 跟 size
    # 这里的 fileLen 指的是整个二进制文件的长度
    fileLen = Path(staticLibPath).stat().st_size
    # 从 magic number 占用空间后开始
    offset = 8
    while offset < fileLen:
    # 解析 object_header， 目的是在拆解成一个一个的.o目标文件，
    # 返回的是实际的符号表大小， 名称和起始偏移位置
    # 这里可以重用resolver_object_header的原因是， object_header 和符号表头结构一致，所以可以同一个函数处理。
        (name, location, size) = resolver_object_header(offset)
        
        # offset 更新为object_header 的偏移， 跳过了符号表 + 字符串标
        offset = location+size
        endIndex = name.find('.o')
        # 找到的不是.o 目标文件直接跳过， 从符号表表头，会跳过符号表， 字符串标，以及目标表头等
        if endIndex == -1:
            #静态库的符号表，不需要处理
            continue
        # 预处理数据查找符号
        process_object_file(name[:endIndex], location, size)
        
        # 所有的符号位置都替换成 hook msg_send()
    if len(symtabList_loc_size) > 0:
        replace_Objc_MsgSend(fileLen)



'''
首先静态库是二进制文件，所以需要了解静态库的结构才能解析，通常使用的 ar 也是这样处理的
头八个字节是 magic = '!<arch>\n',
'''
