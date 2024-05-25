#!/usr/bin/env python3

import asyncio
import json
import aiohttp
from aiolimiter import AsyncLimiter
from credentialthreat.core import utils


class ScanerCrtsh:
    def __init__(self) -> None:
        self.results: set = set()

    async def crtsh(self, session: aiohttp.ClientSession, request_input, rate_limit):
        try:
            async with rate_limit:
                response = await session.get('https://crt.sh/?', params=request_input, headers=utils.get_header())
                if response.status == 200:
                    data1 = await response.text()
                    data = json.loads(data1)
                    for crt in data:
                        for domains in crt['name_value'].split('\n'):
                            if '@' in domains:
                                continue

                            if domains not in self.results:
                                domains_trans = domains.lower().replace('*.', '').rstrip('.')
                                self.results.add(domains_trans)

        except (asyncio.TimeoutError, TypeError, json.decoder.JSONDecodeError) as e:
            print('Subdomain Scan error occurred in crtsh: ', e)

        except aiohttp.ClientConnectorError as e:
            print('Server Connection Error via crt.sh Subdomain Scan: ', e)

        except Exception as e:
            print('Other Error occured with crt.sh Subdomain Scan: ', e)

    async def tasks_subdomains_crtsh(self, fuzzy_results: list, session: aiohttp.ClientSession):
        parameters = [{'q': '%.{}'.format(y), 'output': 'json'} for y in fuzzy_results]
        rate_limit = AsyncLimiter(1, 10)
        tasks = [self.crtsh(session, symbol, rate_limit) for symbol in parameters]
        await asyncio.gather(*tasks)

    async def get_results(self, fuzzy_results: list, session: aiohttp.ClientSession) -> set:
        await self.tasks_subdomains_crtsh(fuzzy_results, session)
        return self.results
