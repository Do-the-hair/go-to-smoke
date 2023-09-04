import argparse
import requests
import re
import json
import threading
import aiohttp
import asyncio

proxies = {}

class HttpClientHandle:
    stopFlag = False
    def __init__(self):
        self.loop = asyncio.get_event_loop()
        self.tasks = []
        
    def addRequest(self, runable, about, *args, **kwargs):
        task = self.loop.create_task(self.reqTask(runable, about, *args, **kwargs))
        self.tasks.append(task)
    
    async def loopTask(self):
        while not self.stopFlag:
            print(self.stopFlag)
            await asyncio.sleep(1)
        
        while True:
            okTask, waitTask = await asyncio.wait(self.tasks)
            if len(waitTask) == 0:
                return
    def stop(self):
        self.stopFlag = True
    
    def start(self):
        self.loop.run_until_complete(self.loopTask())

    async def reqTask(self, runable, about, *args, **kwargs):
        #try:
            async with aiohttp.ClientSession() as client:
                async with client.get(*args, **kwargs) as resp:
                    await runable(about, resp)
        #except Exception as a:
        #    print('except: ' + str(a))
            
# 计算需要请求的页面与过滤掉的选项
def calcPageAndCounts(beg, end, count):
    pageBeg = 0
    pageEnd = None
    itemBeg= 0
    itemEnd= None
    
    pageBeg = beg//count
    itemBeg = beg%50
    if end is not None:
        pageEnd = ((end-1)//count)+1
        itemEnd= end-(beg-(beg%count))
        
    return {'pageBeg': pageBeg, 'pageEnd': pageEnd, 'itemBeg': itemBeg, 'itemEnd': itemEnd}

''' 搜索 CVE '''
class CveDetails:
    def __init__(self, baseUrl='https://www.cvedetails.com', proxies=None):
        self.baseUrl = baseUrl
        self.proxies = proxies
        
    # 获得所有标题 
    def getCveTitles(self, html):
        # 获得table标签内容
        html = re.sub('[\r\n]', '', html)
        table = re.search('<table class="searchresults[^>]*>(.*?)(?=</table>)', html).group(1)
        # 获得所有标题
        titles = re.findall(r'<th[^>]*>(.*?)(?=</th>)',table)
        return [text.strip() for text in titles]
        
    # 获得所有页url
    def getPageList(self, html):
        return re.findall('"([^"]+)"	 title="Go to page ',html)

    # 获得页面内所有的CVE信息
    def getCvePageInfo(self, url):
        resp = requests.get(self.baseUrl + url, proxies=self.proxies)
        # 获得table标签内容
        html = re.sub('[\r\n]', '',resp.text)
        table = re.search('<table class="searchresults[^>]*>(.*?)(?=</table>)', html).group(1)
        # 获得内容
        cveDetails = re.findall(r'<tr class="srrowns">(.*?)(?=</tr>)', table)
        
        cveList=[]
        for infos in cveDetails:
            infoList = re.findall(r'<td[^>]*>(.*?)(?=</td>)', infos)
            infoList = [re.sub(r'<[^>]*?>', '', info).strip() for info in infoList]
            cveList += [infoList]
        return cveList

    def searchOfUrl(self, url, beg=0, end=None):
        resp = requests.get(self.baseUrl+url, proxies=self.proxies)
        vulList = re.search('/vulnerability-list/[^"]+',resp.text)
        if vulList is not None:
            url = vulList.group(0)

        resp = requests.get(self.baseUrl+url, proxies=self.proxies)
        # 获得所有页url
        cvePages = self.getPageList(resp.text)
        
        # 没有其他页面时
        if cvePages == []:
            return self.getCvePageInfo(url)[beg:end]
            
        # 计算所需请求页面与过滤
        limit = calcPageAndCounts(beg, end, len(cvePages))    
        cveList = []
        cvePages = cvePages[limit['pageBeg']:limit['pageEnd']]
        for page in cvePages:
           cveList += self.getCvePageInfo(page)

        return cveList[limit['itemBeg']:limit['itemEnd']]
        
    # 查找销售公司
    def searchOfVendor(self,name, beg = 0, end = None):
        return self.searchOfUrl('/vendor-search.php?search={}'.format(name), beg, end)
        
    # 查找指定产品
    def searchOfProduct(self,name, beg = 0, end = None):
        return self.searchOfUrl('/product-search.php?vendor_id=0&search={}'.format(name), beg, end)

class CveMitre:
    def __init__(self, baseUrl='https://cve.mitre.org', proxies=None):
        self.baseUrl = baseUrl
        self.proxies = proxies

    def searchOfName(self, name, beg = 0, end = None):
        resp = requests.get(self.baseUrl+'/cgi-bin/cvekey.cgi?keyword='+name, proxies=self.proxies)
        cvelist = re.findall(r'<td valign="top" nowrap="nowrap"[^>]*>([^\r\n]*)', resp.text)
        output=[]
        for index in range(len(cvelist)):
            output += [[index + 1, re.sub('<[^>]*>', '', cvelist[index])]]
        #cvelist = [['x', re.sub('<[^>]*>', '', x)] for x in cvelist]
        return output[beg:end]
        
''' 搜索 EXP '''
class GithubQuery:
    githubTokens = [
        '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',
        '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',
        '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',
        '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',
    ]
    tokenIndex = 0
    def __init__(self, githubTokens = None, proxies = None):
        if githubTokens is not None:
            self.githubTokens = githubTokens 
        self.proxies = proxies

    def queryGithub(self, url):
        resp = requests.get(url, headers={'Authorization':'token '+self.githubTokens[self.tokenIndex]}, proxies=self.proxies)
        self.tokenIndex = (self.tokenIndex + 1) % len(self.githubTokens)
        return resp
        
    def findExp(self, cve):
        resp = self.queryGithub('https://api.github.com/search/repositories?q='+cve)
        if (resp.status_code != 200):
            exit('github 请求失败!' + resp.text)
            
        respJs = json.loads(resp.text)
        return respJs['total_count'] > 0
        
    def asyncFindExp(self, httpIo, cveList):
        pass
        
    def finalFind(self, cve, resp):
        pass

    def getAsyncResult(self):
        pass
        
class ExpDb:
    searchUrl = '/search?cve={}&draw=2&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=0&order%5B0%5D%5Bdir%5D=desc&start=0&length=15&search%5Bvalue%5D=&search%5Bregex%5D=false'
    def __init__(self, baseUrl='https://www.exploit-db.com', proxies=None):
        self.baseUrl = baseUrl
        self.proxies = proxies
    
    def findExp(self, cve):
        cve = cve[4:]
        resp = requests.get(self.baseUrl+self.searchUrl.format(cve), headers={'X-Requested-With': 'XMLHttpRequest'}, proxies=self.proxies)
        return len(json.loads(resp.text)['data']) > 0
    
    def asyncFindExp(self, httpIo, cveList):
        self.foundCve = []
        for cve in cveList:
            self.works = httpIo.addRequest(self.finalFind, cve, self.baseUrl+self.searchUrl.format(cve[4:]), headers={'X-Requested-With': 'XMLHttpRequest'})#, proxies=self.proxies
            
    async def finalFind(self, cve, resp):
        html = await resp.text()
        if len(json.loads(html)['data']) > 0:
            print('[+] expdb Found ' + cve)
            self.foundCve.append(cve)
        
    def getAsyncResult(self):
        return self.foundCve
        
class PacketStormSecurity:
    def __init__(self, baseUrl='https://packetstormsecurity.com', proxies=None):
        self.baseUrl = baseUrl
        self.proxies = proxies
    
    def findExp(self, cve):
        resp = requests.get(self.baseUrl + '/search/?q='+cve, proxies=self.proxies)
        return resp.text.find('<a href="/files/tags/exploit">exploit</a>') != -1
        
    def asyncFindExp(self, httpIo, cveList):
        self.foundCve = []
        for cve in cveList:
            self.works = httpIo.addRequest(self.finalFind, cve, self.baseUrl + '/search/?q='+cve)#, proxies=self.proxies
        
    async def finalFind(self, cve, resp):
        html = await resp.text()
        if html.find('<a href="/files/tags/exploit">exploit</a>') != -1:
            print('[+] pack sec Found '+cve)
            self.foundCve += [cve]

    def getAsyncResult(self):
        return self.foundCve

def usage():
    parser = argparse.ArgumentParser(description='Get cvedetails.com cvelist.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cve-mitre', '-cm', dest='mitre', metavar='vmware', type=str, nargs='?',help='使用cvemitre搜索关键字')
    group.add_argument('--vendor', '-v', dest='vendor', metavar='vmware', type=str, nargs='?',help='搜索公司')
    group.add_argument('--product', '-p', dest='product', metavar='workstation', type=str, nargs='?',help='搜索产品')
    group.add_argument('--url', '-u', dest='url', metavar='/vendor-search.php?search=xxx', type=str, nargs='?',help='所有在cvedetails中存在列表视图的url')
    group.add_argument('--file', '-f', dest='infile', type=str, nargs='?',help='cve列表文件')
    parser.add_argument('--limit-beg', '-lb', dest='limit_beg', metavar='x', default=0,type=int, nargs='?',help='过滤起始位置')
    parser.add_argument('--limit-end', '-le', dest='limit_end', metavar='x', default=None,type=int, nargs='?',help='过滤终止位置')
    parser.add_argument('--proxy', '-px', dest='proxy', metavar='socks5://xxx.xxx.xxx.xxx/', default=None,type=str, nargs='?',help='使用代理')
    parser.add_argument('--verify-github', '-vg',action='store_true', dest='verifyGithub',help='github验证')
    parser.add_argument('--verify-expdb', '-ve',action='store_true', dest='verifyExpDb',help='ExpDb验证')
    parser.add_argument('--verify-packet-sec', '-vps',action='store_true', dest='verifyPacketSec',help='PacketStormSecurity验证')
    parser.add_argument('--verify-all', '-va',action='store_true', dest='verifyAllSource',help='验证所有源')
    parser.add_argument('--verify-async', '-vs',action='store_true', dest='verifyAsync',help='异步验证')
    parser.add_argument('--outfile', '-o', metavar='xxx.txt/xxx.csv', dest='outfile', help='输出文件')
    args = parser.parse_args()
    return args
    
def chooseSearchSource(args):
    # 选择搜索类
    if args.vendor is not None:
        searchFunc = details.searchOfVendor
        url = args.vendor
    elif args.product is not None:
        searchFunc = details.searchOfProduct
        url = args.product
    elif args.mitre is not None:
        searchFunc = mitreCls.searchOfName
        url = args.mitre
    else:
        searchFunc = details.searchOfUrl
        url = args.url
    return searchFunc,url

def asyncSearchSource(verifyClass, cves):
    verifyCves={}
    if len(verifyClass) == 0:
        return cves
        
    http = HttpClientHandle()
    thr = threading.Thread(target=http.start)
    thr.start()
    
    cveNums = [x[1] for x in cves]
    for name, verifyObj in verifyClass.items():
        verifyObj.asyncFindExp(http, cveNums)
            
    http.stop()
    thr.join()
    for name, verifyObj in verifyClass.items():
        for cve in verifyObj.getAsyncResult():
            if verifyCves.get(cve) == None:
                verifyCves[cve].append(name)
            else:
                verifyCves[cve].append(name)
                
    return verifyCves
    
def syncSearchSource(verifyClass, cves):
    # 无验证
    verifyCves={}
    if len(verifyClass) == 0:
        return cves
    
    for cve in cves:
        for name, verifyObj in verifyClass.items():
            try:
                if not verifyObj.findExp(cve[1]):
                    print('[-] ({}) {}不存在{}'.format(cve[0], name, cve[1]))
                    continue

                print('[+] ({}) {}存在{}'.format(cve[0], name, cve[1]))
                if verifyCves.get(cve[1]) == None:
                    verifyCves[cve[1]] = [name]
                else:
                    verifyCves[cve[1]] += [name]
            except:
                print('cve请求失败' + cve[1])
                
    return verifyCves
    
if __name__ == '__main__' :

    args = usage()    
    if args.proxy is not None:
        proxies = {
            'http': args.proxy,
            'https': args.proxy,
        }
        
    if args.verifyAsync and args.proxy is not None and not args.proxy.startswith('http://'):
        exit('aiohttp only http proxies are supported')
    
    # 初始化类
    details = CveDetails(proxies=proxies)
    mitreCls = CveMitre(proxies=proxies)
    github = GithubQuery(proxies=proxies)
    expDb = ExpDb(proxies=proxies)
    packetSec = PacketStormSecurity(proxies=proxies)

    searchFunc,url = chooseSearchSource(args)
    
    # 搜索CVE
    verifyCves = {}
    cves = searchFunc(url, args.limit_beg, args.limit_end)
    for i in cves:
        print(i[1])
    print('[+] 找到cve数量：{}'.format(len(cves)))
    
    # 设置验证CVE类
    verifyClass = {}
    if args.verifyAllSource != False:
        args.verifyGithub = args.verifyExpDb = args.verifyPacketSec = True
    
    if args.verifyGithub != False:
        verifyClass['github'] = github
    if args.verifyExpDb != False:
        verifyClass['ExpDb'] = expDb
    if args.verifyPacketSec != False:
        verifyClass['PacketStormSecurity'] = packetSec
    
    if args.verifyAsync != False:
        asyncSearchSource(verifyClass, cves)
    else:
        syncSearchSource(verifyClass, cves)