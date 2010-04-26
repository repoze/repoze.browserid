repoze.browserid
================

Browser id middleware for WSGI, loosely based on the Zope 2 concept
of browser ids, which are cookies which represent a browser, for use
by sessioning libraries.

Browser Id
----------

The concept of a browser id is simple: every request to an application
which is fronted by the browser id middleware will include a browser
id within the WSGI environment.  A browser id is an opaque string that
is guaranteed to be unique within the set of all individual user
agents which visit the application over the lifetime of that
application.  This string is most useful as a key in a sessioning
system.

If a user agent contacts the application but does not supply a browser
id, one will be manufactured for the current request, and a Set-Cookie
header will be returned to the user agent, which it will (hopefully)
return on subsequent requests.

If the user agent does supply a cookie containing a browser id but the
cookie value is tampered with by the user or by some middleman, it
will be rejected, and a new browser id will be constructed for the
current request.

We set the browser id value as ``repoze.browserid`` in the WSGI environ
before we call the downstream application.  It is a 40-character
string.

Uniqueness
----------

The browser id machinery guarantees uniqueness of browser ids by
composing the browser id out of three coponents: a random component, a
time component, and a component representing the pid of the process
serving the application.  The "true" randomness of the random
component is guaranteed within a one-second window by specialized
code, which, when coupled with the time component, guarantees good
uniqueness of browser ids.

Tamper Checking and Varying
---------------------------

The cookie set by the browser id middleware is forgery-resistant.

The cookie value of Set-Cookie headers created by the middleware is
composed of three parts: the browser id (a unique 40-character
string), a delimiter ("!"), and an HMAC of the browser id serialized
as a 32-character string.

When configuring the browserid middleware, you must supply a secret
key.  The middleware uses the secret key and "vary" values to compose
the "tamper key" when creating a browser id.  The tamper key is
composed of the secret key concatenated with values provided in the
environment.  Varying allows a configurer to vary the tamper key on,
e.g. ``REMOTE_ADDR`` if he believes that the same browser id should
always be sent from the same IP address, or ``HTTP_USER_AGENT`` if he
believes it should always come from the same user agent, or some
arbitrary combination thereof made out of environ keys.

When the cookie is composed, An HMAC of the browser id is computed
using the tamper key.  The HMAC is appended to the browser id after a
delimiter character.  When a browser id is retrieved from a user
agent, the HMAC portion is separated from the browser id and a new
HMAC using the same secret key and vary values is computed.  If the
cookie HMAC matches the computed HMAC, the cookie hasn't been tampered
with, and the browser id portion of the cookie becomes the browser id
for the current request.  If they differ, a new browser id is
generated.

Configuration
-------------

Configuration via Python
~~~~~~~~~~~~~~~~~~~~~~~~

Wire up the middleware in your application::

 from repoze.browserid.middleware import BrowserIdMiddleware
 middleware = BrowserIdMiddleware(app, secret_key='foo',
                                  cookie_name='repoze.browserid',
                                  cookie_path='/',
                                  cookie_domain=None,
                                  cookie_lifetime=None,
                                  cookie_secure=None,
                                  vary=())


Configuration via Paste
~~~~~~~~~~~~~~~~~~~~~~~

Use the ``egg:repoze.browserid#browserid`` entry point in your Paste
configuration, eg.::

      [filter:browserid]
      use = egg:repoze.browserid#browserid
      secret_key = foo

      [pipeline:main]
      pipeline = egg:Paste#cgitb
                 browserid
                 myapp

API Documentation
-----------------

.. automodule:: repoze.browserid.middleware

   .. autoclass:: BrowserIdMiddleware

   .. autofunction:: make_middleware

Reporting Bugs / Development Versions
-------------------------------------

Visit http://bugs.repoze.org to report bugs.  Visit
http://svn.repoze.org to download development or tagged versions.

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
