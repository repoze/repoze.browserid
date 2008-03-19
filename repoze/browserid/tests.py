import unittest

class TestBrowserIdMiddleware(unittest.TestCase):
    def _getTargetClass(self):
        from repoze.browserid.middleware import BrowserIdMiddleware
        return BrowserIdMiddleware

    def _makeOne(self, *arg, **kw):
        klass = self._getTargetClass()
        app = DummyApp()
        return klass(app, *arg, **kw)

    def test_defaults_nocookie(self):
        middleware = self._makeOne('thecookiename')
        environ = {}
        headerses = []
        def start_response(status, headers, exc_info=None):
            headerses.append(headers)
        import time
        dummy_t = DummyTime(0, time.gmtime(0), '<timestr>')
        dummy_random = DummyRandom(0)
        app_iter = middleware(environ, start_response, time=dummy_t,
                              random=dummy_random)
        headers = headerses[0]
        self.assertEqual(len(headers), 1)
        header = headers[0]
        self.assertEqual(header[0], 'Set-Cookie')
        self.assertEqual(header[1], 'thecookiename=' + '0' * 40 + '; Path=/; ')

    def test_defaults_withcookie(self):
        middleware = self._makeOne('thecookiename')
        environ = {'HTTP_COOKIE':'thecookiename=1'}
        headerses = []
        def start_response(status, headers, exc_info=None):
            headerses.append(headers)
        result = middleware(environ, start_response)
        self.assertEqual(headerses, [[]])

class TestMakeBrowserId(unittest.TestCase):
    def _getFUT(self):
        from repoze.browserid.middleware import make_browser_id
        return make_browser_id

    def test_it(self):
        f = self._getFUT()
        time = DummyTime(0)
        random = DummyRandom(0)
        browser_id = f(time, random)
        self.assertEqual(browser_id, '0' * 40)

class TestMakeTimestamp(unittest.TestCase):
    def _getFUT(self):
        from repoze.browserid.middleware import make_timestamp
        return make_timestamp

    def test_zero(self):
        t = DummyTime(0)
        f = self._getFUT()
        ts = f(t)
        self.assertEqual(ts, '0'*32)

    def test_mah_birthday(self):
        import time
        mah_birthday = (1971, 5, 10, 0, 0, 0, 0, 0, -1)
        mah_birthday = time.mktime(mah_birthday)
        t = DummyTime(mah_birthday)
        f = self._getFUT()
        ts = f(t)
        self.assertEqual(ts, '00000000028b7d400000000000000000')

class TestTimestampToTime(unittest.TestCase):
    def _getFUT(self):
        from repoze.browserid.middleware import timestamp_to_time
        return timestamp_to_time

    def test_zero(self):
        f = self._getFUT()
        stamp = '0' * 32
        t = f(stamp)
        self.assertEqual(t, 0)

    def test_mah_birthday(self):
        import time
        mah_birthday = (1971, 5, 10, 0, 0, 0, 0, 0, -1)
        mah_birthday = time.mktime(mah_birthday)
        f = self._getFUT()
        stamp = '00000000028b7d400000000000000000'
        t = f(stamp)
        self.assertEqual(t, mah_birthday)

    def test_hexdecode_bad(self):
        f = self._getFUT()
        stamp = 'bogus'
        t = f(stamp)
        self.assertEqual(t, None)

    def test_unpack_bad(self):
        f = self._getFUT()
        stamp = '0' * 16 # not long enough
        t = f(stamp)
        self.assertEqual(t, None)

class TestTimeFromBrowserId(unittest.TestCase):
    def _getFUT(self):
        from repoze.browserid.middleware import time_from_browser_id
        return time_from_browser_id

    def test_working(self):
        browser_id = '0' * 40
        f = self._getFUT()
        t = f(browser_id)
        self.assertEqual(t, 0)

    def test_bogus(self):
        f = self._getFUT()
        stamp = '0' * 16 # not long enough
        t = f(stamp)
        self.assertEqual(t, None)

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
    
    def test_finish_response(self):
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
