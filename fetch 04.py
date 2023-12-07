import re
import os
import time
import json
import base64
import random
import string
import zipfile
import logging
import requests

'''
    安装此库的方法：
        pip install crypto
        pip install pycryptodome
        然后把 Python 安装目录下 ./Lib/site-packages/crypto 改成首字母大写的 Crypto
'''
from Crypto.Cipher import AES

class logger:
    name = 'fetch'
    path = './log/fetch.log'
    format = '%(asctime)s [%(levelname)s] (%(funcName)s: %(lineno)d): %(message)s'

    def __init__(self):
        '''
            初始化日志

            保存成的文件会在 ./log/fetch.log 下
                通过 path 可以改变保存位置
            
            默认在控制台输出所有级别的日志，
            在文件中只写入 INFO 及以上级别的日志
        '''

        self.logger = logging.getLogger(self.name)
        # 默认不向父记录器传递日志信息
        self.logger.propagate = False
        self.format = logging.Formatter(self.format)

        self.console = logging.StreamHandler()
        self.console.setLevel(logging.INFO)
        self.console.setFormatter(self.format)
        self.logger.addHandler(self.console)

        self.file = logging.FileHandler(
              filename=self.path, mode='a', encoding='utf-8')
        self.file.setLevel(logging.INFO)
        self.file.setFormatter(self.format)
        self.logger.addHandler(self.file)

        self.logger.setLevel(logging.INFO)
    
    def __del__(self):
        '''
            析构函数，清空记录器绑定，避免重复输出
        '''
        
        self.logger.handlers.clear()

log = logger()

class authserver:
    session = None

    username = ''
    password = ''

    def encrypt_password(self, password_seed:str)->str:
        '''
            返回加密后的密码
            From 某学长的 Github: https://github.com/NJU-uFFFD/DDLCheckerCrawlers/blob/main/crawlers/NjuSpocCrawler.py
            逆向 javascript 得到的加密代码，使用 Python 重写

            password_seed: AES 加密算法的参数
        '''
        random_iv = ''.join(random.sample((string.ascii_letters + string.digits) * 10, 16))
        random_str = ''.join(random.sample((string.ascii_letters + string.digits) * 10, 64))

        data = random_str + self.password
        key = password_seed.encode("utf-8")
        iv = random_iv.encode("utf-8")

        bs = AES.block_size

        def pad(s):
            return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        data = cipher.encrypt(pad(data).encode("utf-8"))
        return base64.b64encode(data).decode("utf-8")

    def need_captcha(self):
        '''
            和网站交互，确定验证码
        '''

        need_url = f'https://authserver.nju.edu.cn/authserver/needCaptcha.html'
        res = self.session.post(need_url, data={'username': self.username})
        return 'true' in res.text

    def get_captch(self, online:bool)->str:
        '''
            获取验证码的结果并返回
        
            online: 是否调用在线付费 API 识别验证码
        '''

        if self.need_captcha():
            captch_url = 'https://authserver.nju.edu.cn/authserver/captcha.html'
            captch_img = self.session.get(captch_url).content

            if online:
                captch_img = 'data:image/jpg;base64,{}'.format(
                    base64.b64encode(captch_img).decode('utf-8'))
                
                data = {
                    'image': captch_img,
                    'token': '-aiEOVLTyt9yoOmq6cLvYrKejQGimynQieo3IjO1k44',
                    'type': 10110
                }
                headers = {
                    'Content-Type': 'application/json'
                }
                res = requests.post('http://api.jfbym.com/api/YmServer/customApi',
                                    data = json.dumps(data), headers=headers)
                if res.status_code == 405:
                    log.logger.error('OCR 接口拒绝服务：返回值 405，请检查 P 认证')
                    raise Exception('OCR 接口拒绝服务')
                else:
                    res = res.json()
                    if res['code'] == 10000:
                        return res['data']['data']
                    elif res['code'] == 10002:
                        log.logger.error(f'OCR 接口欠费，接口返回：{res}')
                        raise Exception('OCR 接口欠费，请联系开发人员处理')
                    else:
                        log.logger.error(f'''OCR 接口遇到未知错误，错误码：{res['code']}''')
                        raise Exception(f'''OCR 接口遇到未知错误，错误码：{res['code']}''')
            else:
                # 本地存档一份当前验证码
                with open('chaptch.jpg', 'wb') as img_output:
                    img_output.write(captch_img)
                return input('请输入验证码：')
        else:
            log.logger.error('从统一身份认证网站获取验证码失败，无法与服务器建立联系')
            raise Exception('从统一身份认证网站获取验证码失败，请检查网络连接')
        
    def login(self, online:bool=True):
        '''
            统一身份认证登录，无返回，会建立的一个 session 会话，
            在外部通过 <authserver_object>.session.get/post() 可以顺利访问需要认证的页面

            online: 是否调用在线付费 API 识别验证码，默认调用
        '''

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'})

        index_url = 'https://authserver.nju.edu.cn/authserver/login?service=http%3A%2F%2Fzzfwx.nju.edu.cn%2Fwec-self-print-app-console%2Fadmin%2Flogin%2FIDS%3FreturnUrl%3D%252F'
        index_page = self.session.get(index_url).content.decode('utf-8')

        password_seed = re.search(r'pwdDefaultEncryptSalt = \"(.*?)\"', index_page).group(1)

        form = {
            'username': self.username,
            'password': self.encrypt_password(password_seed),
            'captchaResponse': self.get_captch(online),
            'lt': re.search(r'name="lt" value="(.*?)"', index_page).group(1),
            'execution': re.search(r'name="execution" value="(.*?)"', index_page).group(1),
            '_eventId': re.search(r'name="_eventId" value="(.*?)"', index_page).group(1),
            'rmShown': re.search(r'name="rmShown" value="(.*?)"', index_page).group(1),
            'dllt': 'userNamePasswordLogin',
        }
        
        login_url = 'https://authserver.nju.edu.cn/authserver/login'
        res = self.session.post(url=login_url, data=form, allow_redirects=False)
        
        if res.status_code == 302:
            return self.session
        else:
            log.logger.error(f'登录失败，请检查用户名和密码是否正确，\
                             服务器返回值：{res.status_code}')
            raise Exception('登录失败，请检查用户名和密码是否正确')

class printer:
    session = None
    id_map = {
        '本科学位证明': '1373833631222497282',
        '本科毕业证明': '1354632827907375105',
        '英文电子成绩单': '1252873888887504897',
        '中文电子成绩单': '1252793153417674754',
        '中英文在学证明': '1202512333918732289',
        '英文自助打印成绩单': '1202512253492953090',
        '中文自助打印成绩单': '1202512157040738305',
        '中文在学（学籍）证明': '1202512079915876353'
    }
    
    def __init__(self, session:object):
        '''
            传入统一身份认证的 session

            session: 统一身份认证成功后的 session
        '''

        self.session = session
        self.session.headers.update({
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'Connection': 'keep-alive',
            'Content-Type': 'application/json',
            'LoginMode': 'ADMIN',
            'Origin': 'http://zzfwx.nju.edu.cn',
            'Referer': 'http://zzfwx.nju.edu.cn/wec-self-print-app-console/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'appId': '80019'
        })

        # 访问自助打印网站，获取专有 Cookies
        self.session.get(
            'http://zzfwx.nju.edu.cn/wec-self-print-app-console/admin/login/IDS?&returnUrl=/')

    @staticmethod
    def compare_name(name_1, name_2):
        return name_1 == name_2

    def get_url(self, item_name:str, stu_id:int, stu_name:str):
        '''
            获取 stu_id（学号）对应 item_name 类型的材料

            item_name: 材料类型
            stu_id: 学生学号
            stu_name: 学生中文姓名
        '''

        params = {
            # 选择的证明文件种类，每一种都有固定的
            'itemId': self.id_map[item_name],
            # 代表导出方案为单个导出
            'schemeId': '1166533502928420866',
            # 学号
            'ID': stu_id,
            'pageNumber': '1',
            'pageSize': '10',
        }

        # 验证学号是否正确
        res_1 = self.session.get(
            'http://zzfwx.nju.edu.cn/wec-self-print-app-console/item/sp-batch-export/item/user/page',
            params=params, verify=False
        )
        
        res_1 = res_1.json()
        # 登录失败则返回的 data 为空
        if not res_1['data']:
            log.logger.error(f'''资料获取失败，错误：{res_1['msg']}，服务器返回：{res_1}''')
            raise Exception(f'''登录失效，服务器报错：{res_1['msg']}''')
        
        name_list = res_1['data']['records']
        if name_list == []:
            log.logger.error(f'资料获取失败，未查询到学号 {stu_id} 对应的学生 {stu_name}')
            raise Exception('学号错误')
        
        # 学生姓名与系统获取姓名不匹配，则退出
        if not self.compare_name(name_list[0]['NAME'], stu_name):
            log.logger.error(f'''资料获取失败，学号为 {stu_id} 的学生\
                填写姓名 "{stu_name}" 与获取姓名 "{name_list[0]['NAME']}" 不匹配''')
            raise Exception('姓名错误')

        json_data = {
            'itemId': self.id_map[item_name],
            'itemName': item_name,
            'users': [
                {
                    'id': name_list[0]['ID'],
                    'name': name_list[0]['NAME'],
                },
            ],
            'groupUserIds': '',
            'singleUserCount': '50',
            'schemeId': '1166533502928420866',
            'groupBy': ''
        }

        # 获取任务 id
        res_2 = self.session.post(
            'http://zzfwx.nju.edu.cn/wec-self-print-app-console/item/sp-batch-export/task/create',
            json=json_data, verify=False
        )
        
        # 获取下载 url
        url = 'http://zzfwx.nju.edu.cn/wec-self-print-app-console/item/sp-batch-export/task/{}'\
            .format(res_2.json()['data'])

        for counter in range(0, 10):
            time.sleep(3)
            res_3 = self.session.get(url=url, verify=False)
            download_url = res_3.json()['downloadUrl']
            if download_url != None:
                return download_url
        
        # 30s 仍然无法获得下载链接，结束并返回获取失败
        log.logger.error('资料下载失败，获取下载链接轮询超时')
        raise Exception('资料下载失败，获取下载链接超时')

class fetcher:
    uid = 0
    auth = None
    printer = None
    user_data = {}
    admin_path = './admin.config'
    user_data_path = './data/{}.dat'
    user_file_path = './files/{}/'

    # 从表格多选项到下载内容的映射
    download_map = {
        '中英文在学证明': [
            {'name': '中英文在学证明', 'file': '中英文在学证明'}
        ],
        '中文电子成绩单': [
            {'name': '中文电子成绩单', 'file': '中文电子成绩单'}
        ],
        '英文成绩单': [
            {'name': '英文电子成绩单', 'file': '英文电子成绩单'}
        ],
        '本科学位证明': [
            {'name': '本科学位证明', 'file': '本科学位证明'}
        ],
        '本科毕业证明': [
            {'name': '本科毕业证明', 'file': '本科毕业证明'}
        ]
    }

    def __init__(self, uid:int):
        '''
            初始化一个用户数据获取对象

            uid: 用户唯一 id
        '''
        # 设置用户 id
        self.uid = uid
        self.read_user_data()
        self.read_admin_data()

    def read_user_data(self):
        '''
            根据用户 id 读取用户数据
        '''

        try:
            with open(
                self.user_data_path.format(self.uid), 
                'r', encoding='utf-8'
            ) as file:
                self.user_data = json.loads(file.read())
            
            if not self.user_data.get('user'):
                log.logger.error(f'读取学生数据出错，请检查学生 {self.uid} 对应信息是否为空')
                raise Exception(f'读取学生数据出错，请检查学生信息是否为空')
        except Exception as err:
            log.logger.log(f'读取学生数据出错，学生 {self.uid}，完整错误：')
            log.logger.exception(err)
            raise Exception(f'读取学生数据出错，错误：{err}')

    def read_admin_data(self):
        '''
            读取管理员数据，
            并实现统一身份认证登录
        '''

        # 统一身份认证登录
        self.auth = authserver()
        try:
            with open(self.admin_path, 'r', encoding='utf-8') as file:
                for line in file.readlines():
                    if 'username' in line:
                        line = line.split('=', 1)
                        self.auth.username = re.sub(r'(^\s+)|(\s+$)', '', line[1]) \
                            if len(line) > 1 else ''
                    elif 'password' in line:
                        line = line.split('=', 1)
                        self.auth.password = re.sub(r'(^\s+)|(\s+$)', '', line[1]) \
                            if len(line) > 1 else ''
            if self.auth.username == '' or self.auth.password == '':
                log.logger.error(f'读取管理员配置文件出错，未能成功获取用户名或密码')
                raise Exception('读取管理员配置文件出错')
            else: self.auth.login()
        except Exception as err:
            log.logger.error(f'统一身份认证失败，错误：{err}')
            raise Exception(f'统一身份认证失败，错误：{err}')

    def store_file(self, url:str, file_name:str):
        '''
            通过 url 下载文件并存入对应目录
        '''

        try:
            # 验证并新建文件夹
            if not os.path.exists(f'./files/{self.uid}'):
                os.mkdir(f'./files/{self.uid}')

            # 写入内容
            # file_data = self.auth.session.get(url).content
            file_path = self.user_file_path.format(self.uid)
            # with open(f'{file_path+file_name}.zip', 'wb') as file:
            #     file.write(file_data)
            
            # 解压缩
            zip_file = zipfile.ZipFile(f'{file_path+file_name}.zip', 'r')

            # 判断压缩文件是否为空
            if len(zip_file.namelist()) < 1:
                log.logger.error(f'解压出错，压缩文件位置：{file_path+file_name}.zip')
                Exception('解压出错，压缩文件为空')
            
            # 解压首个文件
            file = zip_file.namelist()[0]
            zip_file.extract(file, file_path)
            zip_file.close()
            # 修改文件名
            os.rename(file_path+file, f'{file_path+file_name}.pdf')
            os.remove(f'{file_path+file_name}.zip')
        except Exception as err:
            log.logger.error(f'学生 {self.uid} 的资料文件 {file_name} 写入出错，错误：{err}')
            raise Exception(f'文件写入出错，错误：{err}')

    def fetch_data(self):
        try:
            # 初始化爬虫对象
            self.printer = printer(self.auth.session)

            # 获取资料 url 并下载到本地存储文件夹
            stu_id = self.user_data['user']
            stu_name = self.user_data['cn_name']
            for item in self.user_data['list']:
                for mapping in self.download_map[item]:
                    url = self.printer.get_url(mapping['name'], stu_id, stu_name)
                    self.store_file(url, mapping['file'])
        except Exception as err:
            log.logger.error(f'学生 {self.uid} 下载出错，错误：{err}')
            raise Exception(f'下载出错，错误：{err}')

def main(uid:str):
    '''
        主函数，根据 uid 获取学生数据
    '''
    
    # 补全缺少的文件夹
    if not os.path.exists('./files'):
        os.mkdir('files')
    if not os.path.exists('./data'):
        os.mkdir('data')
    if not os.path.exists('./log'):
        os.mkdir('log')
    
    # 开始运行程序
    try:
        fetcher_obj = fetcher(uid)
        fetcher_obj.store_file('', 'a')
        # fetcher_obj.fetch_data()
    except Exception as err:
        print(f'获取资料出错，错误：{err}')

if __name__ == '__main__':
    main('231880291')