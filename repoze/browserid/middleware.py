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

import hmac
import os
import random
import StringIO
import time
import threading
try:
    from hashlib import sha1 as sha
except ImportError: # Python < 2.5
    from sha import new as sha

from paste.request import get_cookies

_RANDS = []
_CURRENT_PERIOD = None
_LOCK = threading.Lock()


class BrowserIdMiddleware(object):

    def __init__(self, app,
                 secret_key,
                 cookie_name,
                 cookie_path='/',
                 cookie_domain=None,
                 cookie_lifetime=None,
                 cookie_secure=False,
                 vary=(),
                 ):
        """
        Construct an object suitable for use as WSGI middleware that
        implements a browser id manager.

        ``app``
           A WSGI application object. Required.

        ``secret_key``
           A string that will be used as a component of the browser id
           tamper key. Required.

        ``cookie_name``
           The cookie name used for the browser id cookie.  Defaults
           to ``repoze.browserid``.

        ``cookie_path``
           The cookie path used for the browser id cookie.  Defaults
           to ``/``.

        ``cookie_domain``
           The domain of the browser id key cookie.  Defaults to ``None``,
           meaning do not include a domain in the cookie.

        ``cookie_lifetime``
           An integer number of seconds used to compute the expires time
           for the browser id cookie.  Defaults to ``None``, meaning
           include no Expires time in the cookie.

        ``cookie_secure``
           Boolean.  If ``True``, set the Secure flag of the browser
           id cookie.

        ``vary``
           A sequence of string header names on which to vary.
        """

        self.app = app
        self.secret_key = secret_key
        self.cookie_name = cookie_name
        self.cookie_path = cookie_path
        self.cookie_domain = cookie_domain
        self.cookie_lifetime = cookie_lifetime
        self.cookie_secure = cookie_secure
        self.vary = vary
        self.randint = random.randint # tests override
        self.time = time.time # tests override
        try:
            self.pid = os.getpid()
        except AttributeError: # pragma: no cover
            # no getpid in Jython
            self.pid = 1

    def __call__(self, environ, start_response):
        """
        If the remote browser has a cookie that claims to contain a
        browser id value, and that value hasn't been tampered with,
        set the browser id portion of the cookie value as
        'repoze.browserid' in the environ and call the downstream
        application.

        Otherwise, create one and set that as 'repoze.browserid' in
        the environ, then call the downstream application.  On egress,
        set a Set-Cookie header with the value+hmac so we can retrieve
        it next time around.

        We use the secret key and the values in self.vary to compose
        the 'tamper key' when creating a browser id, which is used as
        the hmac key.  This allows a configurer to vary the tamper key
        on, e.g. 'REMOTE_ADDR' if he believes that the same browser id
        should always be sent from the same IP address, or
        'HTTP_USER_AGENT' if he believes it should always come from
        the same user agent, or some arbitrary combination thereof
        made out of environ keys.
        """
        cookies = get_cookies(environ)
        cookie = cookies.get(self.cookie_name)
        if cookie is not None:
            # this browser returned a cookie value that claims to be
            # a browser id
            browser_id = self.from_cookieval(environ, cookie.value)
            if browser_id is not None:
                # cookie hasn't been tampered with
                environ['repoze.browserid'] = browser_id
                return self.app(environ, start_response)

        # no browser id cookie or cookie value was tampered with
        now = self.time()
        browser_id = self.new(now)
        environ['repoze.browserid'] = browser_id
        wrapper = StartResponseWrapper(start_response)
        app_iter = self.app(environ, wrapper.wrap_start_response)
        cookie_value = self.to_cookieval(environ, browser_id)
        set_cookie = '%s=%s; ' % (self.cookie_name, cookie_value)
        if self.cookie_path:
            set_cookie += 'Path=%s; ' % self.cookie_path
        if self.cookie_domain:
            set_cookie += 'Domain=%s; ' % self.cookie_domain
        if self.cookie_lifetime:
            expires = time.gmtime(now + self.cookie_lifetime)
            expires = time.strftime('%a %d-%b-%Y %H:%M:%S GMT', expires)
            set_cookie += 'Expires=%s; ' % expires
        if self.cookie_secure:
            set_cookie += 'Secure;'
        wrapper.finish_response([('Set-Cookie', set_cookie)])
        return app_iter

    def from_cookieval(self, environ, cookie_value):
        try:
            browser_id, provided_hmac = cookie_value.split('!')
        except ValueError:
            return None
        key = self._get_tamper_key(environ)
        computed_hmac = hmac.new(key, browser_id).hexdigest()
        if computed_hmac != provided_hmac:
            return None
        return browser_id

    def to_cookieval(self, environ, browser_id):
        key = self._get_tamper_key(environ)
        h = hmac.new(key, browser_id).hexdigest()
        val = '%s!%s' % (browser_id, h)
        return val

    def _get_tamper_key(self, environ):
        key = self.secret_key
        for name in self.vary:
            key = key + environ.get(name, '')
        return key

    def new(self, when):
        """ Returns opaque 40-character browser id

        An example is: e193a01ecf8d30ad0affefd332ce934e32ffce72
        """
        rand = self._get_rand_for(when)
        source = '%s%s%s' % (rand, when, self.pid)
        browser_id = sha(source).hexdigest()
        return browser_id

    def _get_rand_for(self, when):
        """
        There is a good chance that two simultaneous callers will
        obtain the same random number when the system first starts, as
        all Python threads/interpreters will start with the same
        random seed (the time) when they come up on platforms that
        dont have an entropy generator.

        We'd really like to be sure that two callers never get the
        same browser id, so this is a problem.  But since our browser
        id has a time component and a random component, the random
        component only needs to be unique within the resolution of the
        time component to ensure browser id uniqueness.

        We keep around a set of recently-generated random numbers at a
        global scope for the past second, only returning numbers that
        aren't in this set.  The lowest-known-resolution time.time
        timer is on Windows, which changes 18.2 times per second, so
        using a period of one second should be conservative enough.
        """
        period = 1
        this_period = int(when - (when % period))
        _LOCK.acquire()
        try:
            while 1:
                rand = self.randint(0, 99999999)
                global _CURRENT_PERIOD
                if this_period != _CURRENT_PERIOD:
                    _CURRENT_PERIOD = this_period
                    _RANDS[:] = []
                if rand not in _RANDS:
                    _RANDS.append(rand)
                    return rand
        finally:
            _LOCK.release()


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

def asbool(val):
    if isinstance(val, int):
        return bool(val)
    val= str(val)
    if val.lower() in ('y', 'yes', 'true', 't'):
        return True
    return False

def make_middleware(app, global_conf, secret_key,
                    cookie_name='repoze.browserid',
                    cookie_path='/', cookie_domain=None,
                    cookie_lifetime=None, cookie_secure=False,
                    vary=None):
    """
    Return an object suitable for use as WSGI middleware that
    implements a browser id manager.  Usually used as a PasteDeploy
    filter_app_factory callback.

    ``app``
       A WSGI application object. Required.

    ``global_conf``
       A dictionary representing global configuration (PasteDeploy).
       Required.

    ``secret_key``
       A string that will be used as a component of the browser id
       tamper key. Required.

    ``cookie_name``
       The cookie name used for the browser id cookie.  Defaults
       to ``repoze.browserid``.

    ``cookie_path``
       The cookie path used for the browser id cookie.  Defaults
       to ``/``.

    ``cookie_domain``
       The domain of the browser id key cookie.  Defaults to ``None``,
       meaning do not include a domain in the cookie.

    ``cookie_lifetime``
       An integer number of seconds used to compute the expires time
       for the browser id cookie.  Defaults to ``None``, meaning
       include no Expires time in the cookie.

    ``cookie_secure``
       Boolean.  If ``true``, set the Secure flag of the browser id cookie.

    ``vary``
       A space-separated string including the header names on which to vary.
    
    """
    if cookie_lifetime:
        cookie_lifetime = int(cookie_lifetime)
    cookie_secure = asbool(cookie_secure)
    if vary:
        vary = tuple([ x.strip() for x in vary.split() ])
    else:
        vary = ()
    return BrowserIdMiddleware(app, secret_key, cookie_name, cookie_path,
                              cookie_domain, cookie_lifetime, cookie_secure,
                              vary)
    
