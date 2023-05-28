class TYYP():
    def __init__(self,SignToken) -> None:
        self.username = SignToken['tyyp']['username']
        self.password = SignToken['tyyp']['password']

    def int2char(self,a):
        BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
        return BI_RM[a]

    def b64tohex(self,a):
        d = ""
        e = 0
        c = 0
        b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for i in range(len(a)):
            if list(a)[i] != "=":
                v = b64map.index(list(a)[i])
                if 0 == e:
                    e = 1
                    d += self.int2char(v >> 2)
                    c = 3 & v
                elif 1 == e:
                    e = 2
                    d += self.int2char(c << 2 | v >> 4)
                    c = 15 & v
                elif 2 == e:
                    e = 3
                    d += self.int2char(c)
                    d += self.int2char(v >> 2)
                    c = 3 & v
                else:
                    e = 0
                    d += self.int2char(c << 2 | v >> 4)
                    d += self.int2char(15 & v)
        if e == 1:
            d += self.int2char(c << 2)
        return d

    def rsa_encode(self,j_rsakey, string):
        rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        result = self.b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
        return result
    
    def redirect_policy(req, resp):
        lt = req.url.split('lt=')[-1]
        reqId = req.url.split('reqId=')[-1]
        return resp
    
    def Login(self,s,username,password):
        lt = ""
        reqId = ""
        url = "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https%3A%2F%2Fcloud.189.cn%2Fweb%2Fredirect.html"
        try:
            resp = s.get(url)
            for r in resp.history:
                if r.status_code == 302 and "lt=" in r.headers["Location"]:
                    lt = r.headers["Location"].split("lt=")[-1].split("&")[0]
                    reqId = r.headers["Location"].split("reqId=")[-1].split("&")[0]
                    break
            cookies = ";".join([f"{cookie.name}={cookie.value}" for cookie in resp.cookies])
        except Exception as e:
            print(e)
            return "", e

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/74.0",
            "Referer": resp.url,
            "Cookie": cookies,
            "lt": lt,
            "reqId": reqId
        }
        data = {
            "appKey": "cloud",
            "version": "2.0"
        }
        s.headers.update(headers)
        appConfResp = s.post(url="https://open.e.189.cn/api/logbox/oauth2/appConf.do", data=data)
        if not appConfResp.ok:
            print(f"Error fetching app config: {appConfResp.status_code}")
            return "", ValueError("Error fetching app config")
        accountType = json.loads(appConfResp.text)["data"]["accountType"]
        # clientType = json.loads(appConfResp.text)["data"]["clientType"]
        paramId = json.loads(appConfResp.text)["data"]["paramId"]
        mailSuffix = json.loads(appConfResp.text)["data"]["mailSuffix"]
        returnUrl = json.loads(appConfResp.text)["data"]["returnUrl"]

        url = "https://open.e.189.cn/api/logbox/config/encryptConf.do"
        data = {
            "appId": "cloud"
        }
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/74.0",
            "Referer": "https://open.e.189.cn/api/logbox/separate/web/index.html",
            "Cookie": cookies,
        }
        r = s.post(url, data=data, headers=headers, timeout=5)
        pre = r.json()["data"]["pre"]
        pubKey = r.json()["data"]["pubKey"]
        s.headers.update({"lt": lt})
        username = self.rsa_encode(pubKey, username)#util.RsaEncode(bytes(username, "utf8"), pubKey) 
        password = self.rsa_encode(pubKey, password)#util.RsaEncode(bytes(password, "utf8"), pubKey) 
        url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
            'Referer': 'https://open.e.189.cn/',
        }
        data = {
            "version": "v2.0",
            "appKey": "cloud",
            "accountType": accountType,
            "userName": f"{pre}{username}",
            "epd": f"{pre}{password}",
            "validateCode": "",
            "captchaToken": "",
            "returnUrl": returnUrl,
            "mailSuffix": mailSuffix, #"@189.cn",
            "paramId": paramId,
	    #"clientType": client_type,
            #"dynamicCheck": "FALSE",
            #"cb_SaveName": "1",
            #"isOauth2": "false",
        }
        r = s.post(url, data=data, headers=headers, timeout=5)
        if (r.json()['result'] == 0):
            log.info(f"天翼云盘:{r.json()['msg']}")
        else:
            log.info(f"天翼云盘:{r.json()['msg']}")
        try:
            redirect_url = r.json()['toUrl']
            r = s.get(redirect_url)
            return s
        except Exception:
            pass

    def Sgin(self):
        try:
            if self.username != "" and self.password != "":
                s = requests.Session()
                self.Login(s, self.username, self.password)
                rand = str(round(time.time() * 1000))
                surl = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
                url = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN'
                url2 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN'
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
                    "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
                    "Host": "m.cloud.189.cn",
                    "Accept-Encoding": "gzip, deflate",
                    "sessionKey": "9394f5e7-e1f5-4a0a-bcd3-5c2aa5f122df" #所示为例子，新版需要更新sessionKey，获取方式未知 skurl = f'https://api.cloud.189.cn/keepUserSession.action?clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
                }
                # 签到
                response = s.get(surl, headers=headers)
                netdiskBonus = response.json()['netdiskBonus']
                if response.json()['isSign'] == "false":
                    log.info(f"天翼云盘:签到成功，获得：{netdiskBonus}M空间")
                    message =  f"签到成功，获得：{netdiskBonus}M空间"
                else:
                    log.info(f"天翼云盘:已经签到过了，获得：{netdiskBonus}M空间")
                    message =  f"已经签到过了，获得：{netdiskBonus}M空间"

                # 第一次抽奖
                response = s.get(url, headers=headers).json()
                try:
                    if "errorCode" in response:
                        log.info("天翼云盘:第一次抽奖-没有抽奖次数")
                        message += "\n第一次抽奖-没有抽奖次数"
                    else:
                        log.info(f"天翼云盘:第一次抽奖获得{response['prizeName']}")
                        message += f"\n第一次抽奖获得{response['prizeName']}"
                except Exception as er:
                    log.info(f"天翼云盘:第一次抽奖出现了错误:{er}")
                    message += f"\n第一次抽奖出现了错误:{er}"

                # 第二次抽奖
                response = s.get(url2, headers=headers).json()
                try:
                    if "errorCode" in response:
                        log.info("天翼云盘:第二次抽奖-没有抽奖次数")
                        message += "\n第二次抽奖-没有抽奖次数"
                    else:
                        log.info(f"天翼云盘:第二次抽奖获得{response['prizeName']}")
                        message += f"\n第二次抽奖获得{response['prizeName']}"
                except Exception as er:
                    log.info(f"天翼云盘:第二次抽奖出现了错误:{er}")
                    message += f"\n第二次抽奖出现了错误:{er}"
                return message
            else:
                log.info("天翼云盘:账号或密码不能为空")
                return "账号或密码不能为空"
        except Exception as er:
            log.info(f"天翼云盘:出现了错误:{er}")
            return f"出现了错误:{er}"
