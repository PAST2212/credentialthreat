#!/usr/bin/env python3

import asyncio
import json
from bs4 import BeautifulSoup
import aiohttp
from aiolimiter import AsyncLimiter
from credentialthreat.core import utils


class ScanerDnsDumpster:
    def __init__(self) -> None:
        self.results: set = set()

    async def dnsdumpster(self, session: aiohttp.ClientSession, domain, rate_limit):
        try:
            async with rate_limit:
                header = utils.get_header()
                response = await session.get('https://dnsdumpster.com/', headers=header)
                data = {}
                data1 = await response.text()
                soup1 = BeautifulSoup(data1, 'lxml')
                csrfmiddlewaretoken = soup1.find("input", {"name": "csrfmiddlewaretoken"}).attrs.get("value", None)
                if response.status == 200:
                    if 'csrftoken' in response.cookies.keys():
                        csrftoken = str(response.cookies).split('csrftoken=')[1].rsplit(';', 1)[0].strip()
                        data['Cookie'] = f"csfrtoken={csrftoken}"
                        data['csrfmiddlewaretoken'] = csrfmiddlewaretoken
                        data['targetip'] = domain
                        data['user'] = 'free'
                        header['Referer'] = 'https://dnsdumpster.com/'
                        header['Origin'] = 'https://dnsdumpster.com'
                        response2 = await session.post("https://dnsdumpster.com/", data=data, headers=header)
                        data2 = await response2.text()
                        soup2 = BeautifulSoup(data2, 'lxml')
                        subdomains_new = soup2.findAll('td', {"class": "col-md-4"})
                        for subdomain in subdomains_new:
                            subdomain_trans = subdomain.get_text().split()[0].rstrip('.')
                            if domain in subdomain_trans:
                                if subdomain_trans != '':
                                    self.results.add(subdomain_trans)

        except (asyncio.TimeoutError, TypeError, json.decoder.JSONDecodeError) as e:
            print('Subdomain Scan error occurred in dnsdumpster: ', e)

        except aiohttp.ClientConnectorError as e:
            print('Server Connection Error via dnsdumpster Subdomain Scan: ', e)

        except Exception as e:
            print('Other Error occured with dnsdumpster Subdomain Scan: ', e)

    async def tasks_rapiddns(self, fuzzy_results: list, session: aiohttp.ClientSession):
        rate_limit = AsyncLimiter(1, 10)
        tasks = [self.dnsdumpster(session, y, rate_limit) for y in fuzzy_results]
        await asyncio.gather(*tasks)

    async def get_results(self, fuzzy_results: list, session: aiohttp.ClientSession) -> set:
        await self.tasks_rapiddns(fuzzy_results, session)
        return self.results
