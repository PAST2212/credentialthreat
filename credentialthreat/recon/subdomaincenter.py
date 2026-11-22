#!/usr/bin/env python3

import asyncio
import re
import aiohttp
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
from credentialthreat.core import utils
from credentialthreat.core.diagnostics import log_discovery_error


class ScanerSubdomainCenter:
    def __init__(self) -> None:
        self.results: set = set()

    async def subdomaincenter(self, session: aiohttp.ClientSession, domain, rate_limit):
        try:
            async with rate_limit:
                response = await session.get(f"https://api.subdomain.center/?domain={domain}", headers=utils.get_header())
                if response.status == 200:
                    data1 = await response.text()
                    soup = BeautifulSoup(data1, 'lxml')
                    subdomain_trans = re.sub(r'[\[\]"]', "", soup.find('p').get_text()).split(",")
                    for subdomain in subdomain_trans:
                        if subdomain != '':
                            self.results.add(subdomain.rstrip('.'))

        except Exception as e:
            log_discovery_error("Subdomain Center request", e)

    async def tasks_subdomaincenter(self, fuzzy_results: list, session: aiohttp.ClientSession):
        rate_limit = AsyncLimiter(1, 10)
        tasks = [self.subdomaincenter(session, y, rate_limit) for y in fuzzy_results]
        await asyncio.gather(*tasks)

    async def get_results(self, fuzzy_results, session: aiohttp.ClientSession) -> set:
        await self.tasks_subdomaincenter(fuzzy_results, session)
        return self.results
