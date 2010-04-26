import unittest

_DEFAULT_BID = "e193a01ecf8d30ad0affefd332ce934e32ffce72"
_DEFAULT_COOKIE = "%s!1f2115dde0ba7312bdc94942e227666c" % _DEFAULT_BID
# see the "d" at the end?
_BAD_COOKIE = "%s!1f2115dde0ba7312bdc94942e227666d" % _DEFAULT_BID

class TestBrowserIdMiddleware(unittest.TestCase):
    _RANDINT = lambda *arg: 0
    _TIME = lambda *arg: 0
    _PID = 1

    def _getTargetClass(self):
        from repoze.browserid.middleware import BrowserIdMiddleware
        return BrowserIdMiddleware

    def tearDown(self):
        import repoze.browserid.middleware
        repoze.browserid.middleware._RANDS[:] = []
        repoze.browserid.middleware._CURRENT_PERIOD = None
        self.headers = None
        self.status = None
        self.exc_info = None

    def _assertBrowserId(self, browser_id):
        try:
            from hashlib import sha1 as sha
        except ImportError:
            from sha import new as sha
        computed = '%s%s%s' % (self._RANDINT(), self._TIME(), self._PID)
        computed = sha(computed).hexdigest()
        self.assertEqual(browser_id, computed)

    def _assertCookieVal(self, cookie_val, secret='secret'):
        browser_id, provided_hmac = cookie_val.split('!')
        import hmac
        computed_hmac = hmac.new(secret, browser_id).hexdigest()
        self.assertEqual(cookie_val, '%s!%s' % (browser_id, computed_hmac))
        self._assertBrowserId(browser_id)

    def _makeOne(self, *arg, **kw):
        klass = self._getTargetClass()
        app = DummyApp()
        mw = klass(app, *arg, **kw)
        mw.randint = self._RANDINT
        mw.time = self._TIME
        mw.pid = self._PID
        return mw

    def _start_response(self, status, headers, exc_info=None):
        self.status = status
        self.headers = headers
        self.exc_info = exc_info

    def _get_cookie_components(self, cookie_str):
        components =  [ x.strip() for x in cookie_str.rstrip().split(';') if x ]
        return components

    def test_defaults_nocookie(self):
        middleware = self._makeOne('secret', 'thecookiename')
        environ = {}
        app_iter = middleware(environ, self._start_response)
        self.assertEqual(len(self.headers), 1)
        header = self.headers[0]
        header_name, header_val = header
        self.assertEqual(header_name, 'Set-Cookie')
        cookie_val, path = self._get_cookie_components(header_val)
        name, cookie = cookie_val.split('=')
        self.assertEqual(name, 'thecookiename')
        self._assertCookieVal(cookie)
        self.assertEqual(path, 'Path=/')
        self.assertEqual(app_iter, [])

    def test_cookie_path(self):
        middleware = self._makeOne('secret', 'thecookiename',
                                   cookie_path='/subpath')
        environ = {}
        app_iter = middleware(environ, self._start_response)
        self.assertEqual(len(self.headers), 1)
        header = self.headers[0]
        header_name, header_val = header
        self.assertEqual(header_name, 'Set-Cookie')
        cookie_val, path = self._get_cookie_components(header_val)
        name, cookie = cookie_val.split('=')
        self.assertEqual(name, 'thecookiename')
        self._assertCookieVal(cookie)
        self.assertEqual(path, 'Path=/subpath')
        self.assertEqual(app_iter, [])

    def test_cookie_domain(self):
        middleware = self._makeOne('secret', 'thecookiename',
                                   cookie_domain='repoze.org')
        environ = {}
        app_iter = middleware(environ, self._start_response)
        self.assertEqual(len(self.headers), 1)
        header = self.headers[0]
        header_name, header_val = header
        self.assertEqual(header_name, 'Set-Cookie')
        cookie_val, path, domain = self._get_cookie_components(header_val)
        name, cookie = cookie_val.split('=')
        self.assertEqual(name, 'thecookiename')
        self._assertCookieVal(cookie)
        self.assertEqual(path, 'Path=/')
        self.assertEqual(domain, 'Domain=repoze.org')
        self.assertEqual(app_iter, [])

    def test_cookie_lifetime(self):
        lifetime = 86400
        middleware = self._makeOne('secret', 'thecookiename',
                                   cookie_lifetime=lifetime)
        environ = {}
        app_iter = middleware(environ, self._start_response)
        self.assertEqual(len(self.headers), 1)
        header = self.headers[0]
        header_name, header_val = header
        self.assertEqual(header_name, 'Set-Cookie')
        cookie_val, path, expiresh = self._get_cookie_components(header_val)
        name, cookie = cookie_val.split('=')
        self.assertEqual(name, 'thecookiename')
        self._assertCookieVal(cookie)
        self.assertEqual(path, 'Path=/')
        import time
        expires = time.gmtime(lifetime)
        expires = time.strftime('%a %d-%b-%Y %H:%M:%S GMT', expires)
        self.assertEqual(expiresh, 'Expires=%s' % expires)
        self.assertEqual(app_iter, [])

    def test_cookie_secure(self):
        middleware = self._makeOne('secret', 'thecookiename',
                                   cookie_secure=True)
        environ = {}
        app_iter = middleware(environ, self._start_response)
        self.assertEqual(len(self.headers), 1)
        header = self.headers[0]
        header_name, header_val = header
        self.assertEqual(header_name, 'Set-Cookie')
        cookie_val, path, secure = self._get_cookie_components(header_val)
        name, cookie = cookie_val.split('=')
        self.assertEqual(name, 'thecookiename')
        self._assertCookieVal(cookie)
        self.assertEqual(path, 'Path=/')
        self.assertEqual(secure, 'Secure')
        self.assertEqual(app_iter, [])

    def test_defaults_withcookie_untampered(self):
        middleware = self._makeOne('secret', 'thecookiename')
        environ = {'HTTP_COOKIE':'thecookiename=%s; Path=/;' % _DEFAULT_COOKIE}
        result = middleware(environ, self._start_response)
        self.assertEqual(self.headers, [])
        self.assertEqual(result, [])
        self.assertEqual(environ['repoze.browserid'], _DEFAULT_BID)

    def test_defaults_withcookie_tampered_badformat(self):
        middleware = self._makeOne('secret', 'thecookiename')
        middleware.pid = 2 # for varying _DEFAULT_BID
        environ = {'HTTP_COOKIE':'thecookiename=bad; Path=/;'}
        result = middleware(environ, self._start_response)
        # headers were set because the format of the browser id was bad
        self.assertEqual(len(self.headers), 1)
        self.assertEqual(result, [])
        self.assertNotEqual(environ['repoze.browserid'], _DEFAULT_BID)

    def test_defaults_withcookie_tampered_badhmac(self):
        middleware = self._makeOne('secret', 'thecookiename')
        environ = {'HTTP_COOKIE':'thecookiename=%s; Path=/;' % _BAD_COOKIE}
        result = middleware(environ, self._start_response)
        # headers were set because the hmac of the browser id was wrong
        self.assertEqual(len(self.headers), 1)
        self.assertEqual(result, [])
        self.assertEqual(environ['repoze.browserid'], _DEFAULT_BID)

    def test_new(self):
        middleware = self._makeOne('secret', 'thecookiename')
        browser_id = middleware.new(0)
        self._assertBrowserId(browser_id)

    def test_to_cookieval_vary(self):
        middleware = self._makeOne('secret', 'thecookiename')
        middleware.vary = ('REMOTE_ADDR', 'HTTP_USER_AGENT', 'NONEXISTENT')
        environ = {'REMOTE_ADDR':'127.0.0.1', 'HTTP_USER_AGENT':'Fluzbox'}
        browser_id = middleware.new(0)
        cookie_val = middleware.to_cookieval(environ, browser_id)
        self._assertCookieVal(cookie_val, secret='secret127.0.0.1Fluzbox')

    def test_from_cookieval_vary(self):
        middleware = self._makeOne('secret', 'thecookiename')
        middleware.vary = ('REMOTE_ADDR', 'HTTP_USER_AGENT', 'NONEXISTENT')
        environ = {'REMOTE_ADDR':'127.0.0.1', 'HTTP_USER_AGENT':'Fluzbox'}
        tamper_key = 'secret127.0.0.1Fluzbox'
        import hmac
        h = hmac.new(tamper_key, _DEFAULT_BID).hexdigest()
        cookieval = '%s!%s' % (_DEFAULT_BID, h)
        browser_id = middleware.from_cookieval(environ, cookieval)
        self._assertBrowserId(browser_id)

    def test_from_cookieval_bad(self):
        middleware = self._makeOne('secret', 'thecookiename')
        cookieval = 'badcookie'
        browser_id = middleware.from_cookieval({}, cookieval)
        self.assertEqual(browser_id, None)

class TestStartResponseWrapper(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.browserid.middleware import StartResponseWrapper
        return StartResponseWrapper

    def _makeOne(self, *arg, **kw):
        plugin = self._getTargetClass()(*arg, **kw)
        return plugin

    def test_ctor(self):
        wrapper = self._makeOne(None)
        self.assertEqual(wrapper.start_response, None)
        self.assertEqual(wrapper.headers, [])
        self.failUnless(wrapper.buffer)
    
    def test_finish_response_extraheaders(self):
        statuses = []
        headerses = []
        datases = []
        closededs = []
        from StringIO import StringIO
        def write(data):
            datases.append(data)
        def close():
            closededs.append(True)
        write.close = close
            
        def start_response(status, headers, exc_info=None):
            statuses.append(status)
            headerses.append(headers)
            return write
            
        wrapper = self._makeOne(start_response)
        wrapper.status = '401 Unauthorized'
        wrapper.headers = [('a', '1')]
        wrapper.buffer = StringIO('written')
        extra_headers = [('b', '2')]
        result = wrapper.finish_response(extra_headers)
        self.assertEqual(result, None)
        self.assertEqual(headerses[0], wrapper.headers + extra_headers)
        self.assertEqual(statuses[0], wrapper.status)
        self.assertEqual(datases[0], 'written')
        self.assertEqual(closededs[0], True)

    def test_finish_response_noextraheaders(self):
        statuses = []
        headerses = []
        datases = []
        closededs = []
        from StringIO import StringIO
        def write(data):
            datases.append(data)
        def close():
            closededs.append(True)
        write.close = close
            
        def start_response(status, headers, exc_info=None):
            statuses.append(status)
            headerses.append(headers)
            return write
            
        wrapper = self._makeOne(start_response)
        wrapper.status = '401 Unauthorized'
        wrapper.headers = [('a', '1')]
        wrapper.buffer = StringIO('written')
        result = wrapper.finish_response([])
        self.assertEqual(result, None)
        self.assertEqual(headerses[0], wrapper.headers)
        self.assertEqual(statuses[0], wrapper.status)
        self.assertEqual(datases[0], 'written')
        self.assertEqual(closededs[0], True)

class TestMakeMiddleware(unittest.TestCase):
    def _getFUT(self):
        from repoze.browserid.middleware import make_middleware
        return make_middleware

    def test_defaults(self):
        f = self._getFUT()
        mw = f(None, None, 'secret')
        self.assertEqual(mw.secret_key, 'secret')
        self.assertEqual(mw.vary, ())

    def test_overrides(self):
        f = self._getFUT()
        mw = f(None, None, 'secret', cookie_name='jar',
               cookie_path='/foo', cookie_domain='.foo.com',
               cookie_lifetime = '10',
               cookie_secure = 'true',
               vary='abc'
               )
        self.assertEqual(mw.secret_key, 'secret')
        self.assertEqual(mw.vary, ('abc',))
        self.assertEqual(mw.cookie_name, 'jar')
        self.assertEqual(mw.cookie_path, '/foo')
        self.assertEqual(mw.cookie_lifetime, 10)
        self.assertEqual(mw.cookie_secure, True)

class TestAsBool(unittest.TestCase):
    def _callFUT(self, val):
        from repoze.browserid.middleware import asbool
        return asbool(val)

    def test_bool(self):
        self.assertEqual(self._callFUT(True), True)
        self.assertEqual(self._callFUT(False), False)

    def test_int(self):
        self.assertEqual(self._callFUT(1), True)
        self.assertEqual(self._callFUT(0), False)

    def test_truestring(self):
        self.assertEqual(self._callFUT('true'), True)

    def test_falsestring(self):
        self.assertEqual(self._callFUT('false'), False)

class DummyTime:
    def __init__(self, timetime, gmtime=None, strftime=None):
        self._timetime = timetime
        self._gmtime = gmtime
        self._strftime = strftime
        
    def time(self):
        return self._timetime

    def gmtime(self, *arg):
        return self._gmtime

    def strftime(self, fmt, val):
        return self._strftime

class DummyRandom:
    def __init__(self, val):
        self._val = val
        
    def randint(self, start, end):
        return self._val
        
class DummyApp:
    def __call__(self, environ, start_response):
        start_response('200 OK', [])
        return []
