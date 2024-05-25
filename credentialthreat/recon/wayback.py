import aiohttp
from aiolimiter import AsyncLimiter
import asyncio
import json
import datetime
from credentialthreat.core import utils

# scan URLS from root domains.
# Need to get a better understanding of wayback rate limits


class ScanerWaybackMachine:
    def __init__(self) -> None:
        self.excluding_byte_mimetypes = 'warc/revisit|image/avif|image/jpeg|image/jpg|image/png|image/svg.xml|image/gif|image/tiff|image/webp|image/bmp|image/vnd|image/x-icon|image/vnd.microsoft.icon|font/ttf|font/woff|font/woff2|font/x-woff2|font/x-woff|font/otf|audio/mpeg|audio/wav|audio/webm|audio/aac|audio/ogg|audio/wav|audio/webm|video/mp4|video/mpeg|video/webm|video/ogg|video/mp2t|video/webm|video/x-msvideo|video/x-flv|application/font-woff|application/font-woff2|application/x-font-woff|application/x-font-woff2|application/vnd.ms-fontobject|application/font-sfnt|application/vnd.android.package-archive|binary/octet-stream|application/octet-stream|application/pdf|application/x-font-ttf|application/x-font-otf|video/webm|video/3gpp|application/font-ttf|audio/mp3|audio/x-wav|image/pjpeg|audio/basic|application/font-otf'
        self.including_status_codes = '200|202'
        self.to_date_year = datetime.date.today().year
        self.from_date_year = self.to_date_year - 2
        self.limit_results = 100000
        self.results: set = set()

    async def hackertarget(self, session: aiohttp.ClientSession, fqdn, rate_limit):
        try:
            async with rate_limit:
                url = f'https://web.archive.org/cdx/search/cdx?url={fqdn}/*&output=json&fl=original&collapse=urlkey&filter=!mimetype:{self.excluding_byte_mimetypes}&filter=statuscode:{self.including_status_codes}&limit={self.limit_results}&from={self.from_date_year}&to={self.to_date_year}'
                response = await session.get(url, headers=utils.get_header())
                if response.status == 200:
                    data = await response.text()
                    list_transform = data.replace('[', '').replace(']', '').replace('"', '').strip().lower().replace("\n", "")
                    rows = list_transform.split(',')
                    if len(rows) > 1:
                        for row in rows[1:]:
                            if len(row) > 1:
                                url = row.strip().lower()
                                self.results.add(url)

                else:
                    print('Other Status code occcured at wayback machine', response.status)


        except (TypeError, json.decoder.JSONDecodeError) as e:
            print(f'{type(e)}: Wayback Machine Fecth URL Error for fqdn: {fqdn}. Error Message: {e}')

        except (aiohttp.ClientConnectorError, aiohttp.ServerConnectionError, asyncio.TimeoutError) as e:
            print(f'{type(e)}: Wayback Machine Connection Error for fqdn: {fqdn}. Error Message: {e}')

        except Exception as e:
            print(f'{type(e)}: Wayback Machine Connection Error for fqdn: {fqdn}. Error Message: {e}')

    async def tasks_wayback(self, fqdn_list: list, session: aiohttp.ClientSession):
        rate_limit = AsyncLimiter(1, 10)
        tasks = [self.hackertarget(session, y, rate_limit) for y in fqdn_list]
        await asyncio.gather(*tasks)

    async def get_results(self, fqdn_list, session: aiohttp.ClientSession):
        await self.tasks_wayback(fqdn_list, session)
        return self.results
