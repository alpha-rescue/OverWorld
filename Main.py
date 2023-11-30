
import random
import string
import time
from hashlib import md5
from threading import Thread

import cloudscraper
import requests
import warnings

import ua_generator
from eth_account.messages import encode_defunct

from logger import logger
from web3 import Web3
from web3.auto import w3

warnings.filterwarnings("ignore", category=DeprecationWarning)


def generate_random_number(length: int) -> int:
    return int(''.join([random.choice(string.digits) for _ in range(length)]))

def generate_csrf_token() -> str:
    random_int: int = generate_random_number(length=3)
    current_timestamp: int = int(str(int(time.time())) + str(random_int))
    random_csrf_token = md5(string=f'{current_timestamp}:{current_timestamp},{0}:{0}'.encode()).hexdigest()
    return random_csrf_token

class Model:

    def __init__(self, email, proxy, private, twitter_auth, logger=None):
        self.logger = logger

        self.ua = self.generate_user_agent

        self.twitter_auth, self.twitter_ct0 = twitter_auth, generate_csrf_token()
        self.twitterHeaders = {'cookie': f'auth_token={self.twitter_auth}; ct0={self.twitter_ct0}',
                               'Authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                               'content-type': 'application/x-www-form-urlencoded',
                               'X-Csrf-Token': self.twitter_ct0,
                               'user-agent': self.ua
                               }

        w3 = Web3(Web3.HTTPProvider('https://eth.llamarpc.com'))
        account = w3.eth.account.from_key(private)
        # print(account.address)

        self.private, self.address = private, account.address
        self.email = email
        self.session = self._make_scraper
        self.proxy = proxy
        self.session.proxies = {"http": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}",
                                "https": f"http://{proxy.split(':')[2]}:{proxy.split(':')[3]}@{proxy.split(':')[0]}:{proxy.split(':')[1]}"}

        adapter = requests.adapters.HTTPAdapter(max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.session.headers.update({"user-agent": self.ua,
                                     'content-type': 'application/json'})

    def Registration(self):

        payload = {"balance":0,
                   "wallet_address":self.address,
                   "network":
                       {"name":"homestead",
                        "chainId":1,
                        "ensAddress":"0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"}
                   }

        response = self.session.post("https://owapi.ovrwrld.net/applicants", json=payload)

        self.uuid = response.json()['uuid']

        message = encode_defunct(text=self.uuid)
        signed_message = w3.eth.account.sign_message(message, private_key=self.private)
        self.signature = signed_message["signature"].hex()

        payload = {
                   "signed_message": self.signature
                   }

        response = self.session.post(f"https://owapi.ovrwrld.net/applicants/{self.uuid}/message", json=payload)
        return response.json()


    def TwitterConnect(self):

        with self.session.get(f"https://owapi.ovrwrld.net/applicants/{self.uuid}/twitter/connect?redir=https://whitelist.overworld.games", allow_redirects=False) as response:
            link = response.headers['Location']

            with self.session.get(link.replace('https://twitter.com/i/oauth2/authorize?', 'https://twitter.com/i/api/2/oauth2/authorize?'), headers=self.twitterHeaders) as response:
                auth_code = response.json()['auth_code']

                payload = {'approval': 'true',
                           'code': auth_code}

                response = self.session.post(f'https://twitter.com/i/api/2/oauth2/authorize', data=payload, headers=self.twitterHeaders)
                # print(response.json()['redirect_uri'])

                with self.session.get(response.json()['redirect_uri']) as response:
#                     print(response.text)
                    ...

    def MakeTasks(self):
        response = self.session.post(f"https://owapi.ovrwrld.net/applicants/{self.uuid}/tweet", json={})
        time.sleep(random.randint(1,5))

        payload = {"questions_and_answers":[["What interests you about Overworld?",random.choice(Qs[0])],
                                            ["How do you plan on supporting the community and project?",random.choice(Qs[1])],
                                            ["What Web3 communities are you a part of?",random.choice(Qs[2])],
                                            ["To receive notifications about future mints and product updates please enter your email address",self.email],
                                            ["I consent to receiving email communication from Xterio",random.choice([True, False])]]}

        response = self.session.post(f"https://owapi.ovrwrld.net/applicants/{self.uuid}/questionnaire", json=payload)
        return response.json()

    @property
    def generate_user_agent(self) -> str:
        return ua_generator.generate(platform="windows").text

    @property
    def _make_scraper(self):

        return cloudscraper.create_scraper()


def Thread_(list_):


    count = 0
    while count < len(list_):

        try:


            email = list_[count][0]
            logger.success(f'{email} | Регистрация началась')

            acc = Model(email=list_[count][0],
                        proxy=list_[count][1],
                        private=list_[count][2],
                        twitter_auth=list_[count][3],
                        logger=logger)

            stat = acc.Registration()
            if stat == False:
                logger.error(f'{email} | Ошибка с почтой')
                continue

            logger.success(f'{email} | Регистрация успешно произведена')

            acc.TwitterConnect()
            logger.success(f'{email} | К аккаунту успешно подключен твиттер')

            # input()

            result = acc.MakeTasks()
            # print(result)
            logger.success(f'{email} | Все задания выполнены')


            with open('results.txt', 'a+') as file:
                file.write('{}|{}|{}|{}\n'.format(acc.email, acc.private, acc.twitter_auth, acc.proxy))

            time.sleep(random.randint(delayAccs[0],delayAccs[1]))

        except Exception as e:

            # traceback.print_exc()
            logger.error(f'{email} | Ошибка - {str(e)}')

        time.sleep(random.randint(delayAccs[0], delayAccs[1]))
        logger.debug('')

        # input()
        count += 1


def split_list(lst, n):
    k, m = divmod(len(lst), n)
    return list(lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

if __name__ == '__main__':

    proxies = []
    emails = []
    privates = []
    twitterData = []

    Qs=[]

    delayAccs = (10, 30)
    threads = 1

    for index in range(3):
        ds = []
        with open(f'InputData/Qs/Q{index+1}.txt', 'r') as file:
            for i in file:
                ds.append(i.rstrip().split(':')[0])
        Qs.append(ds)

    with open('InputData/Emails.txt', 'r') as file:
        for i in file:
            emails.append(i.rstrip().split(':')[0])
    with open('InputData/Proxies.txt', 'r') as file:
        for i in file:
            proxies.append(i.rstrip())
    with open('InputData/Privates.txt', 'r') as file:
        for i in file:
            privates.append(i.rstrip())
    with open('InputData/TwitterCookies.txt', 'r') as file:
        for i in file:
            twitterData.append(i.rstrip().split('auth_token=')[-1].split(';')[0])

    resultList = []
    for i in range(len(proxies)):
        resultList.append([emails[i], proxies[i], privates[i], twitterData[i]])

    result = split_list(resultList, threads)

    threads_ = []
    for i in result:

        t = Thread(target=Thread_, args=(i,))
        threads_.append(t)

    for i in threads_:
        i.start()

    for i in threads_:
        i.join()

    input('Скрипт завершил работу...')


