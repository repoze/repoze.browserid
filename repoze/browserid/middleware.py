##############################################################################
#
# Copyright (c) 2008 Agendaless Consulting and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the BSD-like license at
# http://www.repoze.org/LICENSE.txt.  A copy of the license should accompany
# this distribution.  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL
# EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND
# FITNESS FOR A PARTICULAR PURPOSE
#
##############################################################################

import random
import sys
import StringIO
import struct
import time

from paste.request import get_cookies

class BrowserIdMiddleware(object):
    def __init__(self, app,
                 cookie_name,
                 cookie_path='/',
                 cookie_domain=None,
                 cookie_lifetime=None,
                 cookie_secure=False):

        self.app = app
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_domain = cookie_domain
        self.cookie_lifetime = cookie_lifetime
        self.cookie_secure = cookie_secure

    def __call__(self, environ, start_response, time=time, random=random):
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)
        if cookie is not None:
            # this browser already has an id
            return self.app(environ, start_response)
            
        wrapper = StartResponseWrapper(start_response)
        app_iter = self.app(environ, wrapper.wrap_start_response)
        browser_id = make_browser_id(time, random)
        set_cookie = '%s=%s; ' % (self.cookie_name, browser_id)
        if self.cookie_path:
            set_cookie += 'Path=%s; ' % self.cookie_path
        if self.cookie_domain:
            set_cookie += 'Domain=%s; ' % self.cookie_domain
        if self.cookie_lifetime:
            expires = time.gmtime(time.time() + self.cookie_lifetime)
            expires = time.strftime('%a %d-%b-%Y %H:%M:%S GMT', expires)
            set_cookie += 'Expires=%s; ' % expires
        if self.cookie_secure:
            set_cookie += 'Secure;'
        wrapper.finish_response([('Set-Cookie', set_cookie)])
        return app_iter

def make_browser_id(time=time, random=random):
    """ Returns 40-character string browser id
    'AAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
    where:

    A == 8-byte string representation of random integer
    B == 32-byte hex representation of a timetime value

    An example is: 0000000047e0d7e3000000006468f3ff
    """
    rand = random.randint(0, 99999999)
    stamp = make_timestamp(time)
    browser_id = '%08i%s' % (rand, stamp)
    return browser_id

def time_from_browser_id(browser_id):
    stamp = browser_id[8:]
    return timestamp_to_time(stamp)
        
def make_timestamp(time=time):
    now = time.time()
    int_part = int(now)
    frac_part = int((now - int_part) * sys.maxint)
    stamp = struct.pack(">QQ", int_part, frac_part).encode('hex')
    return stamp

def timestamp_to_time(stamp):
    try:
        binary = stamp.decode('hex')
    except TypeError:
        return None
    try:
        int_part, frac_part = struct.unpack('>QQ', binary)
    except struct.error:
        return None
    frac_part = float(frac_part / sys.maxint)
    time = int_part + frac_part
    return time

class StartResponseWrapper(object):
    def __init__(self, start_response):
        self.start_response = start_response
        self.status = None
        self.headers = []
        self.exc_info = None
        self.buffer = StringIO.StringIO()

    def wrap_start_response(self, status, headers, exc_info=None):
        self.headers = headers
        self.status = status
        self.exc_info = exc_info
        return self.buffer.write

    def finish_response(self, extra_headers):
        if not extra_headers:
            extra_headers = []
        headers = self.headers + extra_headers
        write = self.start_response(self.status, headers, self.exc_info)
        if write:
            self.buffer.seek(0)
            value = self.buffer.getvalue()
            if value:
                write(value)
            if hasattr(write, 'close'):
                write.close()
