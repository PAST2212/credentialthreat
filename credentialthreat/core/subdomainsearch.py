#!/usr/bin/env python3

import asyncio
import aiohttp
from credentialthreat.recon.crtsh import ScanerCrtsh
from credentialthreat.recon.subdomaincenter import ScanerSubdomainCenter
from credentialthreat.recon.rapiddns import ScanerRapidDns
from credentialthreat.recon.dnsdumpster import ScanerDnsDumpster


class ScanerSubdomains:
    def __init__(self):
        self.subdomains = set()

    async def tasks_subdomains(self, iterables: list) -> None:
        timeout = aiohttp.ClientTimeout(total=None, sock_read=30, sock_connect=30)
        async with aiohttp.ClientSession(timeout=timeout) as session1, aiohttp.ClientSession(timeout=timeout) as session2, aiohttp.ClientSession(timeout=timeout) as session3, aiohttp.ClientSession(timeout=timeout) as session4:
            subs = await asyncio.gather(ScanerCrtsh().get_results(iterables, session1),
                                        ScanerRapidDns().get_results(iterables, session2),
                                        ScanerSubdomainCenter().get_results(iterables, session3),
                                        ScanerDnsDumpster().get_results(iterables, session4)
                                        )
            for sub in subs:
                self.subdomains.update(sub)

    def get_results(self, iterables: list) -> set:

        asyncio.run(self.tasks_subdomains(iterables))

        return self.subdomains
