#!/usr/bin/env python
#-*- coding: utf-8 -*-

'''该脚本按照《海云V8.0精简版部署手册》中的步骤对服务器
进行配置，并安装相关的介质
'''

import subprocess
from time import sleep
from os import geteuid,path,makedirs,rename,environ
from sys import exit
import re
from resource import setrlimit,getrlimit,RLIMIT_NOFILE
import httplib
import json
import socket
import sys
from commands import getoutput
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
from ESScript  import ESScript

EnableLocalYum=False   ####是否开启本地YUM源开关，如果开启就跳过对Internet的检测  2018-02-26 新增   ####

TextColorRed='\x1b[31m'
TextColorGreen='\x1b[32m'
TextColorWhite='\x1b[0m'

validAppNameList=['java','imagemagick','openoffice',
                 'elasticsearch','logstash','nginx',
                 'redis','rabbitmq']


CPUCores='1' if getoutput("lscpu|grep '^CPU(s)'|awk '{print $2}'")=='1' else getoutput("lscpu|grep '^CPU(s)'|awk '{print $2}'")

AppInstalledState={}   ###已经成功安装的软件名称会存放在这里###

WikiURL='http://t.cn/REQVj8w'         #### WIKI 部署文档短地址   ##

def checkRootPrivilege():
###  检查脚本的当前运行用户是否是 ROOT ###
  RootUID=subprocess.Popen(['id','-u','root'],stdout=subprocess.PIPE).communicate()[0]
  RootUID=RootUID.strip()
  CurrentUID=geteuid()
  return str(RootUID)==str(CurrentUID)

def extractLocalIP():
    return subprocess.Popen("ip addr|grep 'state UP' -A2|tail -n1|awk '{print $2}'|cut -f 1 -d '/'",
                            shell=True,stdout=subprocess.PIPE).communicate()[0].strip()

def checkPortState(host='127.0.0.1',port=9200):
### 检查对应服务器上面的port 是否处于TCP监听状态 ##

    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    try:
       s.connect((host,port))
       return {'RetCode':0,
               'Result':TextColorGreen+str(host)+':'+str(port)+'处于监听状态'+TextColorWhite}
    except:
       return {'RetCode':1,
               'Result':TextColorRed+'无法访问'+str(host)+':'+str(port)+TextColorWhite}

def checkCompilerState():
#### 检查C,C++ 编译器状态   ###
    errorA=subprocess.Popen(['which','c++'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
    errorB=subprocess.Popen(['which','gcc'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]

    if errorA or errorB:
       print (TextColorRed+'GCC或者C++编译器尚未安装，即将联网进行安装....'+TextColorWhite)
       InternetState=checkInternetConnection()
       if InternetState['RetCode']!=0:
          print (TextColorRed+InternetState['Description']+' 程序退出!'+TextColorWhite)
          exit(1)
       print (TextColorGreen+InternetState['Description']+TextColorWhite)
       if subprocess.call('yum install -y gcc gcc-c++',shell=True):
           print (TextColorRed+'联网安装GCC,C++ 编译器失败！程序退出!')
           exit(1)
    print (TextColorGreen+'GCC,C++ 编译器已经安装成功!'+TextColorWhite)
         
def __checkOSVersion():
#### 检查操作系统的版本，确保是Centos 7 的版本 ###
    OSInfoFileList=['/etc/centos-release']
    for filepath in OSInfoFileList:
      if path.isfile(filepath):
         TmpFileObj=open(filepath,mode='r')
         FileContent=TmpFileObj.read()
         FileContent=FileContent.strip()
         TmpFileObj.close()
         ReObj=re.search(r'\s+([\d\.]+)\s+',FileContent)
         if ReObj and ('CentOS' in FileContent):
            OSVersion=ReObj.group(1)
            if re.search(r'^7.*',OSVersion):
               print (TextColorGreen+'操作系统满足要求!'+TextColorWhite)
               return 0
            else:
               print (TextColorRed+'操作系统不满足要求(需要CentOS7)，当前系统:'+str(FileContent)+'\n程序退出!'+TextColorWhite)
               exit(1)
    print (TextColorRed+'无法获取操作系统版本信息，或者版本不符合要求(需要CentOS7)'+'\n程序退出!'+TextColorWhite)
    exit(1)
    

          

def configureServerArgument():
#### 修改/etc/security/limits.conf 将max open-file-descriptors 修改成65535
#### 由于不确定业务账号与平台的关联性，因此可能存在部分账号nofile 参数值
#### 被调大的可能性。

    if not  checkRootPrivilege():
       print (TextColorRed+"安装失败：安装过程需要使用root账号，请切换至root账号，然后重试!"+TextColorWhite)
       exit(1)

    #### 修改前先备份原始文件 ####
    if not path.isfile(r'/etc/security/limits.conf.backup'):
        subprocess.call(['cp','/etc/security/limits.conf','/etc/security/limits.conf.backup'])
 
    ReObj=re.compile(r'^\s*[^#]*nofile\s*(?P<value>\d*)\s*$')
    InputFile=open(r'/etc/security/limits.conf',mode='r')

    FileContent=''
    for line in InputFile:       ###逐行读取limits.conf，如果当前行配置了nofile且值低于65535,那么值将被修改成65535
       RetObj=ReObj.search(line)
       if RetObj and int(RetObj.group('value'))<65535:
           line=re.sub(r'(^\s*[^#]*nofile\s*)(?P<value>\d*)\s*$',r'\1 65535',line) 
           FileContent+=line+'\n'
           continue
       FileContent+=line
    InputFile.close()

    Matched=re.search(r'#+.*?Codes below.*?#+',FileContent)
    if not Matched:
       FileContent+='#### Codes below are manually added #####\n'
       FileContent+='*     -    nofile    65535\n'

    OutputFile=open(r'/etc/security/limits.conf',mode='w')
    OutputFile.write(FileContent)
    OutputFile.close()
   
    ### 在当前脚本环境中将nofile设置成65535 ###                                            
    setrlimit(RLIMIT_NOFILE,(65535,65535))
           

def installJava():
    try:
       JavaVersionString=subprocess.Popen(['/TRS/APP/jdk1.8/bin/java','-version'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()[1]
    except Exception as e:
       JavaVersionString=str(e)
    ReObj=re.search(r'java version\s+(.*?)\n',JavaVersionString)

    if ReObj and ReObj.group(1).strip('"').startswith('1.8'):
       print (TextColorGreen+'JAVA 版本满足要求(需要JAVA版本8):'+str(ReObj.group(1).strip('"'))+TextColorWhite)
       AppInstalledState['java']='ok'
    else:
       print (TextColorRed+'JAVA版本不满足要求（需要JAVA版本8)！'+TextColorWhite)
       print ('即将安装JAVA 8,请耐心等待........')

       try:
          makedirs('/TRS/APP')
          print (TextColorGreen+'/TRS/APP/目录创建成功!'+TextColorWhite)
       except:
          if not path.isdir('/TRS/APP'):
             print (TextColorRed+'无法创建/TRS/APP/目录，程序退出!'+TextColorWhite)
             AppInstalledState['java']='not ok'
             exit(1)   

          print (TextColorGreen+'/TRS/APP目录已经存在，无需新建!'+TextColorWhite)
       finally:
          pass

       result,error=subprocess.Popen(['tar','-C','/TRS/APP/','-xvzf','install_package/jdk-8u111-linux-x64.tar.gz'],\
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
          
          
       if len(error)>0:
          print (TextColorRed+error+TextColorWhite)
          print (TextColorRed+'错误：无法解压JAVA安装包,程序退出!'+TextColorWhite)
          AppInstalledState['java']='not ok'
          exit(1)
       print (TextColorGreen+'JAVA8压缩包解压完成!'+TextColorWhite)
       try:
          rename(r'/TRS/APP/jdk1.8.0_111','/TRS/APP/jdk1.8')
          print (TextColorGreen+'文件夹已经重命名为jdk1.8'+TextColorWhite)
       except:
          print (TextColorRed+'/TRS/APP目录下包含有一个名为jdk1.8 的文件或目录，重命名操作失败。')
          print(TextColorRed+'请删除或备份该目录（文件夹），并重新运行该脚本!\n'+'安装失败，程序退出!'+TextColorWhite)
          AppInstalledState['java']='not ok'
          exit(1)
          

    #### 配置JAVA 环境变量####
    print ('正在配置JAVA 环境变量，请稍等..........')
    JavaEnvironDict={'JAVA_HOME':'/TRS/APP/jdk1.8',\
            'PATH':'$JAVA_HOME/bin:$PATH',\
            'CLASSPATH':'.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar',
            'JRE_HOME':'/TRS/APP/jdk1.8/jre',
            }
    tmpDict={'JAVA_HOME':environ.get('JAVA_HOME'),\
             'PATH':environ.get('PATH'),
             'CLASSPATH':environ.get('CLASSPATH'),
             'JRE_HOME':environ.get('JRE_HOME')
            }
    
    if tmpDict['JAVA_HOME']!=JavaEnvironDict['JAVA_HOME'] or tmpDict['CLASSPATH']!=JavaEnvironDict['CLASSPATH']:
       environ['JAVA_HOME']=JavaEnvironDict['JAVA_HOME']
       environ['CLASSPATH']=JavaEnvironDict['CLASSPATH']
       environ['PATH']=JavaEnvironDict['JAVA_HOME']+'/bin:'+tmpDict['PATH']
       environ['JRE_HOME']=JavaEnvironDict['JAVA_HOME']+'/jre' 

### 检查/etc/profile中是否永久配置了JAVA 环境变量###
    InputFile=open(r'/etc/profile','r')
    FileContent=InputFile.read()
    InputFile.close()

    ReObjA=re.search(r'^\s*export\s*JAVA_HOME=/TRS/APP/jdk1\.8\n',FileContent,flags=re.MULTILINE) ## 检查JAVA_HOME ###
    ReObjB=re.search(r'^\s*export\s*CLASSPATH=\.:\$JAVA_HOME/lib/dt\.jar:\$JAVA_HOME/lib/tools\.jar\s*\n',FileContent,flags=re.MULTILINE) ## 检查CLASSPATH ##
    ReObjC=re.search(r'^\s*export\s*JRE_HOME=/TRS/APP/jdk1\.8/jre/?\n',FileContent,flags=re.MULTILINE) ###检查JRE_HOME ###
        
    if (not ReObjA) or (not ReObjB) or (not ReObjC):
       if not path.isfile(r'/etc/profile.backup'):   ###修改前备份/etc/profile ###
          subprocess.call(['cp','/etc/profile','/etc/profile.backup'])

       OutputFile=open(r'/etc/profile',mode='a')
       OutputFile.write('\n')
       OutputFile.write('export  JAVA_HOME='+JavaEnvironDict['JAVA_HOME']+'\n')
       OutputFile.write('export  PATH='+JavaEnvironDict['PATH']+'\n')
       OutputFile.write('export  CLASSPATH='+JavaEnvironDict['CLASSPATH']+'\n')
       OutputFile.write('export  JRE_HOME='+JavaEnvironDict['JRE_HOME']+'\n')
       OutputFile.close()
    AppInstalledState['java']='ok'
    print (TextColorGreen+'JAVA 环境变量配置完毕!'+TextColorWhite)

    ####以下的是拷贝 IDS的补丁，否则IDS无法正常初始化 20171211 新添加####
    if path.isdir(r'/TRS/APP/jdk1.8/jre/lib/amd64'):
       subprocess.call('cp install_package/IDS/libtrscrypt.so /TRS/APP/jdk1.8/jre/lib/amd64',shell=True)
       return

    if path.isdir(r'/TRS/APP/jdk1.8/jre/lib/i386'):
       subprocess.call(r'cp install_package/IDS/libtrscrypt_linux_i386.so /TRS/APP/jdk1.8/jre/lib/i386',shell=True)
       return

       

def checkInternetConnection():
    global EnableLocalYum
    if EnableLocalYum:
        print ('当前开启了本地YUM源，跳过对互联网的检测.')
        return {'RetCode':0,
                'Description':'当前开启了本地YUM源，跳过对Internet的检测'}
    pingResult,pingError=subprocess.Popen(['ping','61.139.2.69','-c 2','-W 1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()
    ReObj=re.search(r'(\d+)\s+received',pingResult)
    PacketRecived=int(ReObj.group(1))
 
    DNSResult,DNSError=subprocess.Popen(['ping','www.baidu.com','-c 1','-W 1'],stdout=subprocess.PIPE,stderr=subprocess.PIPE).communicate()

    if PacketRecived>0 and DNSResult:
        return {'RetCode':0,
                 'Description':'网络畅通，DNS解析正常'}
    elif PacketRecived>0 and DNSError:
        return {'RetCode':1,
                 'Description':'网络畅通，DNS解析异常，请检查DNS服务器设置'}
    else:
        return {'RetCode':2,
                'Description':'无法连接互联网'}
    
    
def installImageMagick_yum():
###虽然最终是通过编译源码的方式安装ImageMagick，
###但是安装过程中涉及到很多依赖包，因此需要
###互联网的接入。
   def __checkImageMagickState():
      tmpDependencyList=['zlib','jpeg','png']
      minVersion='7.0.3'      

      try:
         Result,Error=subprocess.Popen(['/TRS/APP/ImageMagick/bin/convert','-version'],
                                      stdout=subprocess.PIPE).communicate()
         VersionString=re.search(r'Version:\s+ImageMagick\s+([^\s]+)\s',Result,flags=re.MULTILINE).group(1)
         if not (VersionString>=minVersion):
             raise Exception('版本不满足要求: '+str(VersionString))
         
         DelegatesString=re.search(r'Delegates.*?:\s+(.*?)\n',Result,flags=re.MULTILINE).group(1)
        
         ### 检查是否所有的文件格式都支持 ## 
         tmpList=filter(lambda x:x in DelegatesString,tmpDependencyList)  
         if len(tmpList)!=len(tmpDependencyList):
             raise Exception('ImageMagick 支持的文件格式不全')
      except:
         return {'RetCode':1,
                 'Description':'ImageMagick未安装或者安装不满足要求！'}
      else:
         return {'RetCode':0,
                 'Description':'ImageMagick已经安装且满足要求'}
             
         

   InstallationState=__checkImageMagickState()
   if InstallationState['RetCode']==0:
      print (InstallationState['Description'])
      return
   
   print (InstallationState['Description'])
   print (TextColorWhite+'即将安装 ImageMagick,请耐心等待........')
   print (TextColorWhite+'检查互联网网络连接....')
   
   InternetState=checkInternetConnection()
   if InternetState['RetCode']!=0:
      print (TextColorRed+InternetState['Description']+'\nImageMagick安装失败，程序退出！'+TextColorWhite)
      return 1

   CmdInstallGCC=['yum','install','-y','gcc','gcc-c++','openssl']
   CmdInstallDependency=['yum','install','-y',
                         'libjpeg','libjpeg-devel',
                         'libpng','libpng-devel',
                         'zlib','zlib-devel']

   subprocess.call(CmdInstallGCC)
   subprocess.call(CmdInstallDependency)
   print (TextColorGreen+'ImageMagick 依赖包安装完毕!'+TextColorWhite)
 
   print (TextColorWhite+'解压压缩包......')
   try:
      if subprocess.call(['tar','-C','install_package/','-xvzf','install_package/ImageMagick.tar.gz']):
         AppInstalledState['imagemagick']='not ok'
         raise Exception(TextColorRed+"ImageMagick压缩包解压失败，程序退出。"+TextColorWhite)
  
   
      print (TextColorGreen+'解压完成.....'+TextColorWhite)
      print (TextColorWhite+'即将进行编译及安装，该过程会持续一段时间，请耐性等待......'+TextColorWhite)
   
      if subprocess.call(['cd install_package/ImageMagick-7.0.7-13;sh configure --prefix=/TRS/APP/ImageMagick'],shell=True):
          AppInstalledState['imagemagick']='not ok'
          raise Exception(TextColorRed+'ImageMagick编译安装失败，程序退出!'+TextColorWhite)

      if subprocess.call(['cd install_package/ImageMagick-7.0.7-13;make -j %s'%(CPUCores,)],shell=True):
          AppInstalledState['imagemagick']='not ok'
          raise Exception(TextColorRed+'ImageMagick编译安装失败，程序退出!'+TextColorWhite)
      if subprocess.call(['cd install_package/ImageMagick-7.0.7-13;make install'],shell=True):
          AppInstalledState['imagemagick']='not ok'
          raise Exception(TextColorRed+'ImageMagick编译安装失败，程序退出!'+TextColorWhite)
      print (TextColorGreen+'ImageMagick编译安装完毕!'+TextColorWhite)
      AppInstalledState['imagemagick']='ok'
   except Exception as e:
       print (str(e))
       exit(1)
   
   if not path.exists(r'/etc/profile.backup'):
      subprocess.call('cp /etc/profile /etc/profile.backup')

   FileContent=open(r'/etc/profile',mode='rb').read()

   if not re.search(r'^[^#]*/TRS/APP/ImageMagick/TRS/APP/ImageMagick/bin',FileContent,flags=re.MULTILINE):
      subprocess.call("echo 'export  PATH=/TRS/APP/ImageMagick/bin:${PATH}' >>/etc/profile",shell=True)   


def installOpenOffice():
    try:
       print (TextColorWhite+'即将安装OpenOffice,请耐心等待.....'+TextColorWhite)
       if subprocess.call('tar -C install_package/ -xvzf  install_package/Apache_OpenOffice_4.1.4_Linux_x86-64_install-rpm_zh-CN.tar.gz',
                    shell=True,stderr=subprocess.PIPE):
          AppInstalledState['openoffice']='not ok'
          raise Exception(TextColorRed+'OpenOffice压缩包解压失败!'+TextColorWhite)
       
       print (TextColorGreen+'OpenOffice 压缩包解压完毕,即将安装,请稍候.....'+TextColorWhite)
       
       subprocess.call('rpm -Uvih --force install_package/zh-CN/RPMS/*.rpm',shell=True)
       print (TextColorGreen+"OpenOffice安装完毕!"+TextColorWhite)
       AppInstalledState['openoffice']='ok'
    except Exception as e:
       print (e)
       exit(1)

def sendHttpRequest(host='127.0.0.1',port=9200,url='/',method='GET',body={},header={}):
#### 调用特定的 web API,并获取结果 ###
### 函数返回Dict 类型，其中'RetCode'，标识是否异常 0:正常，非0：异常
### 'Result'是具体结果 
    
     try:
        if (not isinstance(body,dict)) or (not isinstance(header,dict)):
            raise Exception(TextColorRed+"需要传入Dict类型，参数调用异常！"+TextColorWhite)

        tmpBody=json.dumps(body)
        HttpObj=httplib.HTTPConnection(host,port)
        HttpObj.request(url=url,method=method,body=tmpBody,headers=header)
        response=json.loads(HttpObj.getresponse().read())
        return {'RetCode':0,
                 'Result':response}
     except Exception as e:
       return {'RetCode':1,
               'Result':TextColorRed+str(e)+TextColorWhite}
        
        


    
def installElasticsearch():
    LocalIPAddr=extractLocalIP()
    if subprocess.call('id -u es',shell=True):  ###首先检查es 账号是否存在###
       print ('ES 账户不存在，需新建。')
       subprocess.call('useradd es',shell=True)
       print (TextColorGreen+'新建ES 账号完成'+TextColorWhite)
       subprocess.call('passwd -l es',shell=True) ####对于通过脚本新建的 es 账号，默认是锁定的(避免弱口令)；其他方式的不受影响###
    else:
       print (TextColorGreen+"ES 账号已经存在。"+TextColorWhite)

    if not path.isdir(r'/TRS/APP'):
       subprocess.call('mkdir -p /TRS/APP/',shell=True)

    if path.exists(r'/TRS/APP/elasticsearch'):
       print (TextColorRed+'检测到/TRS/APP 目录下已经存在一个名为"elasticsearch"的文件或目录，')
       print (TextColorRed+'请删除或对其进行重命名，并重新运行该工具。')
       print (TextColorRed+'Elasticsearch 安装失败，程序退出!'+TextColorWhite)
       AppInstalledState['elasticsearch']='not ok'
       exit(1)

    subprocess.call('tar -C /TRS/APP -xvzf install_package/elasticsearch-5.5.0.tar.gz',shell=True)
    rename(r'/TRS/APP/elasticsearch-5.5.0',r'/TRS/APP/elasticsearch')
    print (TextColorGreen+'Elasticsearch压缩包解压完毕。')

    subprocess.call("sed -i 's/#network\.host: 192\.168\.0\.1/network\.host: 0\.0\.0\.0/g' /TRS/APP/elasticsearch/config/elasticsearch.yml",
                    shell=True)
    
    print (TextColorGreen+'Elasticsearch解压完毕。'+TextColorWhite)

#### 修改操作系统参数 ###

    FileObj=open(r'/etc/security/limits.conf',mode='rb')  ####永久修改 nofile  ###
    FileContent=FileObj.read()
    FileObj.close()

    ReObjA=re.search(r'^\s*es\s+hard\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    ReObjB=re.search(r'^\s*es\s+soft\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    ReObjC=re.search(r'^\s*es\s+-\s+nofile\s+(\d+)\s*$',FileContent,flags=re.MULTILINE)
    
    if ((not ReObjA) or (not ReObjB)) and (not ReObjC):
       if not path.isfile(r'/etc/security/limits.conf.backup'):  ### 修改前先备份  ##
          subprocess.call('cp /etc/security/limits.conf /etc/security/limits.conf.backup',shell=True)
       subprocess.call("echo 'es - nofile 65536' >>/etc/security/limits.conf",shell=True)


####   检查 /etc/sysctl.conf 中vm.max_map_count  的配置情况 ###
    if not path.isfile(r'/etc/sysctl.conf.backup'):
       subprocess.call('cp /etc/sysctl.conf /etc/sysctl.conf.backup',shell=True)

    FileObj=open(r'/etc/sysctl.conf',mode='rb')
    FileContent=FileObj.read()
    FileObj.close()

    tmpList=list(int(x) for x in re.findall(r'^\s*vm.max_map_count\s*=\s*(\d*)\s*$',FileContent,flags=re.MULTILINE))

    if len(tmpList)==0:   ###没有在 /etc/sysctl.conf  中配置vm.max_map_count ###
       subprocess.call("echo 'vm.max_map_count = 655360' >>/etc/sysctl.conf",shell=True)
    elif (len(tmpList)>=1 and max(tmpList)<655360) or (tmpList[-1]<655360):   #### 修正/etc/sysctl.conf 中不不符合要求的vm.max_map_count 参数
       ###首先，删除垃圾数据;然后重新写入###
       FileContent=re.sub(r'^\s*vm.max_map_count\s*=\s*(\d*)\s*$',r'',FileContent,flags=re.MULTILINE)  
       FileObj=open(r'/etc/sysctl.conf',mode='wb')
       FileObj.write(FileContent)
       FileObj.write('vm.max_map_count = 655360'+'\n')
       FileObj.close()


    subprocess.call("chown -R es:es /TRS/APP/elasticsearch",shell=True) 

    print (TextColorGreen+'Elasticsearch 系统参数配置完毕.'+TextColorWhite)

####   添加分词器插件  ####
    subprocess.call('mkdir -p /TRS/APP/elasticsearch/plugins/ik',shell=True)
    subprocess.call('tar -C /TRS/APP/elasticsearch/plugins  -xvzf install_package/ik-ly.5.5.0.tar.gz',shell=True)
    subprocess.call("chown -R es:es /TRS/APP/elasticsearch",shell=True)
    print (TextColorGreen+'elasticsearch分词器安装完毕!'+TextColorWhite)

####   配置分词器 ####
    print ('正在配置elasticsearch分词器，请稍候......')
    subprocess.call('sysctl vm.max_map_count=655360;su - es -c /TRS/APP/elasticsearch/bin/elasticsearch &',shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    print ('正在尝试启动elasticsearch，请稍候......')
    isElasticRunning=False

    for icount in range(5):
         print ('尝试次数:'+str(icount+1))
         sleep(7)
         is9200Listening=checkPortState('127.0.0.1',9200)['RetCode']
         if is9200Listening==0:
            print (TextColorGreen+'Elasticsearch 正在监听9200端口。'+TextColorWhite)
            isElasticRunning=True
            break
         else:
             sleep(5)

    if not isElasticRunning:
         print (TextColorRed+'无法启动Elasticsearch'+TextColorWhite)
         print (TextColorRed+'配置elasticsearch 分词器失败，程序退出!'+TextColorWhite)
         AppInstalledState['elasticsearch']='not ok'
         exit(1)

    ### 创建 index ####
    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/index',method='PUT',header={'Content-Type':'application/json'})

    ### 设置默认分词器## 

    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/index/fulltext/_mapping',
                   method='POST',header={'Content-Type':'application/json'},body=ESScript.DictA)
    
    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/gov_log805',method='PUT',header={'Content-Type':'application/json'})
    tmpresult=sendHttpRequest(host='127.0.0.1',port=9200,url='/gov_log805/logs/_mapping',
                   method='POST',header={'Content-Type':'application/json'},body=ESScript.DictB)

    print (TextColorGreen+'分词器设置完毕。'+TextColorWhite)
    print (TextColorGreen+'Elasticsearch  已经成功安装并配置。'+TextColorWhite)
    AppInstalledState['elasticsearch']='ok'


def installLogstash():
   if path.exists(r'/TRS/APP/logstash'):
      print (TextColorRed+'/TRS/APP 目录下已经存在一个名为logstash的文件或目录，请对其删除或重命名备份，'+TextColorWhite)
      print (TextColorRed+'然后重新运行本工具。'+TextColorWhite)
      print (TextColorRed+'logstash安装失败！\ 程序退出。'+TextColorWhite)
      AppInstalledState['logstash']='not ok'
      exit(1)
   
   if not path.isdir(r'/TRS/APP'):
     subprocess.call('mkdir -p /TRS/APP',shell=True)

   print ('即将解压Logstash,请稍候......')
   subprocess.call('tar -C /TRS/APP -xvzf install_package/logstash-5.5.0.tar.gz',shell=True)
   rename(r'/TRS/APP/logstash-5.5.0',r'/TRS/APP/logstash')
   print (TextColorGreen+'Logstash解压完毕。'+TextColorWhite)
   AppInstalledState['logstash']='ok'
   print (TextColorGreen+'请访问如下地址，完成后续的logstash 配置操作！\n'+WikiURL+TextColorWhite)


def installNginx():
   print (TextColorWhite+'即将编译安装NGINX,请稍候....'+TextColorWhite)
   checkCompilerState()
   subprocess.call('cd  install_package/source_nginx;tar -xvzf nginx-1.13.2.tar.gz',shell=True)
   subprocess.call('cd  install_package/source_nginx;tar -xvzf openssl-1.0.2k.tar.gz',shell=True)
   subprocess.call('cd  install_package/source_nginx;tar -xvzf pcre-8.41.tar.gz',shell=True)
   subprocess.call('cd  install_package/source_nginx;tar -xvzf zlib-1.2.11.tar.gz',shell=True)

   cmdline='cd install_package/source_nginx/nginx-1.13.2;./configure  --with-pcre=../pcre-8.41 --with-zlib=../zlib-1.2.11 \
             --with-openssl=../openssl-1.0.2k --with-stream --with-mail=dynamic \
             --prefix=/TRS/APP/nginx'

   if subprocess.call(cmdline,shell=True):
      print (TextColorRed+'Nginx configure 失败,程序退出。'+TextColorWhite)
      AppInstalledState['nginx']='not ok'
      exit(1)
   print (TextColorGreen+'Nginx configure 成功'+TextColorWhite)

   if subprocess.call('cd install_package/source_nginx/nginx-1.13.2;make -j %s'%(CPUCores,),shell=True):
      print (TextColorRed+'Nginx make 失败，程序退出。'+TextColorWhite)
      AppInstalledState['nginx']='not ok'
      exit(1)

   if subprocess.call('cd install_package/source_nginx/nginx-1.13.2;make install',shell=True):
      print (TextColorRed+'Nginx 安装 失败，程序退出。'+TextColorWhite)
      AppInstalledState['nginx']='not ok'
      exit(1)

   print (TextColorGreen+'Nginx 安装成功'+TextColorWhite)
   AppInstalledState['nginx']='ok'

#####   配置    NGINX 待续  ###
   if not path.exists(r'/etc/profile.backup'):
      subprocess.call('cp /etc/profile /etc/profile.backup',shell=True)

   FileContent=open(r'/etc/profile',mode='rb').read()
   if not re.search(r'^[^#]*/TRS/APP/nginx/sbin/?',FileContent,flags=re.MULTILINE):
      subprocess.call("echo 'export  PATH=/TRS/APP/nginx/sbin:${PATH}' >>/etc/profile",shell=True)
   print (TextColorGreen+'请访问如下地址，完成nginx后续的配置工作\n'+WikiURL+TextColorWhite) 
   

   
def installRedis():
    print (TextColorWhite+'即将安装Redis,请稍候...'+TextColorWhite)
    InternetState=checkInternetConnection()   
    if InternetState['RetCode']!=0:
       print (TextColorRed+InternetState['Description']+TextColorWhite)
       print (TextColorRed+'Redis安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)
    print (TextColorGreen+'网络检测畅通,安装继续。'+TextColorWhite)
    if  subprocess.call('yum install -y tcl gcc gcc-c++',shell=True):
       print (TextColorRed+'联网安装tcl失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)
    if subprocess.call('cd install_package/;tar -xvzf redis-stable.tar.gz',shell=True):
       print (TextColorRed+'解压Redis压缩包失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)

    if subprocess.call('cd install_package/redis-stable;make -j %s'%(CPUCores,),shell=True):
       print (TextColorRed+'Redis 安装失败，程序退出。'+TextColorWhite)
       AppInstalledState['redis']='not ok'
       exit(1)

    if subprocess.call('cd install_package/redis-stable;make install',shell=True):
       print (TextColorRed+'Redis 安装失败，程序退出.'+TextColorGreen)
       AppInstalledState['redis']='not ok'
       exit(1)
#    print (TextColorGreen+'Redis 安装成功.'+TextColorWhite)
    AppInstalledState['redis']='ok'


    ####### 配置 redis #####
    with open(r'install_package/redis_conf/redis',mode='r') as f:
       TmpFileContent=f.read()

    with open(r'/etc/init.d/redis',mode='w') as f:
       f.write(TmpFileContent)

    subprocess.call('chmod 777 /etc/init.d/redis;systemctl daemon-reload',shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with open(r'install_package/redis_conf/redis.conf',mode='r') as f:
        TmpFileContent=f.read()

    TmpRedisPasswd=raw_input('请输入Redis密码，并按回车(直接回车将使用默认密码:trs@admin)：')
    TmpRedisPasswd=TmpRedisPasswd.strip()
    if len(TmpRedisPasswd)==0:
       print (TextColorGreen+'未输入任何密码，使用默认密码'+TextColorWhite)
    else:
       TmpFileContent=re.sub(r'^(\s*requirepass)(.*?)\n',r'\g<1>  '+TmpRedisPasswd+'\n\n',TmpFileContent,flags=re.MULTILINE)

    with open(r'/etc/redis.conf',mode='w') as f:
       f.write(TmpFileContent)

    print (TextColorGreen+'Redis 安装成功.'+TextColorWhite)
       



def installRabbitmq():
   print (TextColorWhite+'安装Rabbitmq，请稍候...'+TextColorWhite)

   ### 新增 对openssl的安装  Added at 2018-03-06 ###
   InternetState=checkInternetConnection()
   if InternetState['RetCode']!=0:
      print (TextColorRed+InternetState['Description']+'\nImageMagick安装失败，程序退出！'+TextColorWhite)
      return 1
   subprocess.call('yum install openssl -y',shell=True)

   

   if  subprocess.call('rpm -Uvh --force install_package/rpm_rabbitmq/erlang/*.rpm',shell=True):
      print (TextColorRed+'erlang 组件安装失败,无法安装Rabbitmq，程序退出！'+TextColorWhite)
      AppInstalledState['rabbitmq']='not ok'
      exit(1)
   print (TextColorGreen+'erlang安装完毕.'+TextColorWhite)

   if subprocess.call('rpm -Uvh --force install_package/rpm_rabbitmq/rabbitmq/*.rpm',shell=True):
      print (TextColorRed+'Rabbitmq安装失败，程序退出.'+TextColorWhite)
      AppInstalledState['rabbitmq']='not ok'
      exit(1)
   print (TextColorGreen+'Rabbitmq 安装完毕.'+TextColorWhite)
   AppInstalledState['rabbitmq']='ok'
   print (TextColorGreen+'请访问如下地址，完成Rabbitmq 后续的配置操作\n'+WikiURL+TextColorWhite)

#### 配置Rabbitmq 待续 #####
    
def __preInstall():
   __checkOSVersion()
 
   global EnableLocalYum 

   for index in range(len(sys.argv)):
       if sys.argv[index]=='-localyum':
          EnableLocalYum=True
          print (TextColorGreen+'当前开启了本地YUM 开关'+TextColorWhite)
          break  
 
  

   try:
      LocalIP=extractLocalIP()
      ### 读取之前已经安装的介质信息，避免重复安装  ###
      if path.isfile(str(LocalIP)+'.log'):
         InputFile=open(LocalIP+'.log',mode='r')
         for line in InputFile:
             TmpList=line.strip().split(':')
             if len(TmpList)>=2:
                name,value=str(TmpList[0]).strip().lower(),str(TmpList[1]).strip().lower()
                if (name in validAppNameList) and (value=='ok'):
                   AppInstalledState[name]=value
                else:
                   print (TextColorRed+'无效的内容'+line+TextColorWhite)
             else:
                 print (TextColorRed+'无效的内容'+line+TextColorWhite)
         InputFile.close() 
      
      checkRootPrivilege()
      configureServerArgument()
   except Exception as e:
      print (TextColorRed+'预安装过程出错：'+str(e)+TextColorWhite)
   finally:
      pass
      

def __postInstall():
    try:
     	LocalIP=extractLocalIP()
    	FileObj=open(str(LocalIP)+'.log',mode='w')
    	for appname in AppInstalledState:
            if AppInstalledState[appname]=='ok':
               FileObj.write(appname+': '+'ok'+'\n')
               continue
            else:
               pass
        FileObj.close()
    except Exception as e:
          print (str(e))
          FileObj.close()
    finally:
          print(TextColorGreen+'介质的安装日志结果保存在当前目录下的:'+str(LocalIP)+'.log'+'文件当中!'+TextColorWhite)


def RunMenu():
    try:
       while True:
          print (TextColorGreen+'#########  欢迎使用“海云系统”，本工具将帮助你完成基础介质的安装。  ######')
          print ('           1、安装 JAVA;')
          print ('           2、安装 ImageMagick;')
          print ('           3、安装 OpenOffice;')
          print ('           4、安装 Elasticsearch;')
          print ('           5、安装 Logstash;')
          print ('           6、安装 Nginx;')
          print ('           7、安装 redis;')
          print ('           8、安装 Rabbitmq;')
          print ('           0、退出安装;'+TextColorWhite)
          
          choice=raw_input('请输入数值序号:')
          choice=choice.strip()
    
          if choice=='1':
             if ('java' in AppInstalledState) and (AppInstalledState['java']=='ok'):
                 print (TextColorGreen+'JAVA 已经安装，无需重复安装'+TextColorWhite)
                 continue
             installJava()
          elif choice=='2':
             if ('imagemagick' in AppInstalledState) and (AppInstalledState['imagemagick']=='ok'):
                 print (TextColorGreen+'ImageMagick 已经安装，无需重复安装'+TextColorWhite)
                 continue
             installImageMagick_yum()
          elif  choice=='3':
             if ('openoffice' in AppInstalledState) and (AppInstalledState['openoffice']=='ok'):
                print (TextColorGreen+'OpenOffice 已经安装，无需重复安装'+TextColorWhite)
                continue
             installOpenOffice()
          elif  choice=='4':
             if ('elasticsearch'  in AppInstalledState) and (AppInstalledState['elasticsearch']=='ok'):
                print (TextColorGreen+' Elasticsearch 已经安装，无需重复安装'+TextColorWhite)
                continue
             installElasticsearch()
          elif  choice=='5':
             if ('logstash'  in AppInstalledState) and (AppInstalledState['logstash']=='ok'):
                print (TextColorGreen+'Logstash 已经安装，无需重复安装'+TextColorWhite)
                continue
             installLogstash()
          elif choice=='6':
             if ('nginx' in AppInstalledState) and (AppInstalledState['nginx']=='ok'):
                print (TextColorGreen+'Nginx 已经安装，无需重复安装'+TextColorWhite)
                continue
             installNginx()
          elif choice=='7':
             if ('redis' in AppInstalledState) and (AppInstalledState['redis']=='ok'):
                print (TextColorGreen+'Redis 已经安装，无需重复安装'+TextColorWhite)
                continue
             installRedis()
          elif  choice=='8':
             if ('rabbitmq'  in AppInstalledState) and (AppInstalledState['rabbitmq']=='ok'):
                print (TextColorGreen+'Rabbitmq 已经安装，无需重复安装'+TextColorWhite)
                continue
             installRabbitmq()
          elif  choice=='0':
             exit(0)
    except:
          pass
    finally:
          __postInstall()
             
      
    

#configureServerArgument()
#installJava()
#installImageMagick_yum()
#installOpenOffice()
#installElasticsearch()
#installLogstash()
#installNginx()
#installRedis()
#installRabbitmq()
#installImageMagick_yum()
#checkCompilerState()



if __name__=='__main__':
  try:
    __preInstall()
    RunMenu()
  except Exception as e:
    print (TextColorRed+'Error:'+str(e)+TextColorWhite)
  finally:
    __postInstall()
   
