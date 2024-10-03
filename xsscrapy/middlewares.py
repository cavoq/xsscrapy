from scrapy.exceptions import IgnoreRequest
from urlparse import unquote
from xsscrapy.bloomfilter import BloomFilter
import random
import re
from xsscrapy.settings import bloomfilterSize

class RandomUserAgentMiddleware(object):
    ''' Use a random user-agent for each request '''
    
    USER_AGENT_LIST = [
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.131 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
        'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/34.0.1847.137 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0'
    ]

    def process_request(self, request, spider):
        ua = random.choice(RandomUserAgentMiddleware.USER_AGENT_LIST)
        if 'payload' in request.meta:
            payload = request.meta['payload']
            if 'User-Agent' in request.headers:
                if payload == request.headers['User-Agent']:
                    return

        request.headers.setdefault('User-Agent', ua)
        request.meta['UA'] = ua

class InjectedDupeFilter(object):
    ''' Filter duplicate payloaded URLs, headers, and forms since all of those have dont_filter = True '''

    URLS_SEEN = BloomFilter(bloomfilterSize)
    FORMS_SEEN = BloomFilter(bloomfilterSize)
    HEADERS_SEEN = BloomFilter(bloomfilterSize)

    def process_request(self, request, spider):

        meta = request.meta
        if 'xss_place' not in meta:
            return
        delim = meta['delim']

        # Injected URL dupe handling
        if meta['xss_place'] == 'url':
            url = request.url
            #replace the delim characters with nothing so we only test the URL
            #with the payload
            no_delim_url = url.replace(delim, '')
            if no_delim_url in InjectedDupeFilter.URLS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded URL: %s' % url)
            InjectedDupeFilter.URLS_SEEN.insert(no_delim_url)
            return

        # Injected form dupe handling
        elif meta['xss_place'] == 'form':
            u = meta['POST_to']
            p = meta['xss_param']
            u_p = (u, p)
            if u_p in InjectedDupeFilter.FORMS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded form param %s to: %s' % (p, u))
            InjectedDupeFilter.FORMS_SEEN.insert(u_p)
            return

        # Injected header dupe handling
        elif meta['xss_place'] == 'header':
            u = request.url
            h = meta['xss_param']
            # URL, changed header, payload
            u_h = (u, h)
            if u_h in InjectedDupeFilter.HEADERS_SEEN:
                raise IgnoreRequest
            spider.log('Sending payloaded %s header' % h)
            InjectedDupeFilter.HEADERS_SEEN.insert(u_h)
            return
