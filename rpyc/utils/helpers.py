"""
Helpers and wrappers for common RPyC tasks
"""
import time
from rpyc.lib import worker
from rpyc.lib.colls import WeakValueDict
from rpyc.lib.compat import callable
from rpyc.core.consts import HANDLE_BUFFITER, HANDLE_CALL
from rpyc.core.netref import syncreq, asyncreq


def buffiter(obj, chunk=10, max_chunk=1000, factor=2):
    """Buffered iterator - reads the remote iterator in chunks starting with
    *chunk*, multiplying the chunk size by *factor* every time, as an
    exponential-backoff, up to a chunk of *max_chunk* size.

    ``buffiter`` is very useful for tight loops, where you fetch an element
    from the other side with every iterator. Instead of being limited by the
    network's latency after every iteration, ``buffiter`` fetches a "chunk"
    of elements every time, reducing the amount of network I/Os.

    :param obj: An iterable object (supports ``iter()``)
    :param chunk: the initial chunk size
    :param max_chunk: the maximal chunk size
    :param factor: the factor by which to multiply the chunk size after every
                   iterator (up to *max_chunk*). Must be >= 1.

    :returns: an iterator

    Example::

        cursor = db.get_cursor()
        for id, name, dob in buffiter(cursor.select("Id", "Name", "DoB")):
            print id, name, dob
    """
    if factor < 1:
        raise ValueError(f"factor must be >= 1, got {factor!r}")
    it = iter(obj)
    count = chunk
    while True:
        items = syncreq(it, HANDLE_BUFFITER, count)
        count = min(count * factor, max_chunk)
        if not items:
            break
        for elem in items:
            yield elem


def restricted(obj, attrs, wattrs=None):
    """Returns a 'restricted' version of an object, i.e., allowing access only to a subset of its
    attributes. This is useful when returning a "broad" or "dangerous" object, where you don't
    want the other party to have access to all of its attributes.

    .. versionadded:: 3.2

    :param obj: any object
    :param attrs: the set of attributes exposed for reading (``getattr``) or writing (``setattr``).
                  The same set will serve both for reading and writing, unless wattrs is explicitly
                  given.
    :param wattrs: the set of attributes exposed for writing (``setattr``). If ``None``,
                   ``wattrs`` will default to ``attrs``. To disable setting attributes completely,
                   set to an empty tuple ``()``.
    :returns: a restricted view of the object

    Example::

        class MyService(rpyc.Service):
            def exposed_open(self, filename):
                f = open(filename, "r")
                return rpyc.restricted(f, {"read", "close"})   # disallow access to `seek` or `write`

    """
    if wattrs is None:
        wattrs = attrs

    class Restricted(object):
        def _rpyc_getattr(self, name):
            if name not in attrs:
                raise AttributeError(name)
            return getattr(obj, name)
        __getattr__ = _rpyc_getattr

        def _rpyc_setattr(self, name, value):
            if name not in wattrs:
                raise AttributeError(name)
            setattr(obj, name, value)
        __setattr__ = _rpyc_setattr
    return Restricted()


class _Async(object):
    """Creates an async proxy wrapper over an existing proxy. Async proxies
    are cached. Invoking an async proxy will return an AsyncResult instead of
    blocking"""

    __slots__ = ("proxy", "__weakref__")

    def __init__(self, proxy):
        self.proxy = proxy

    def __call__(self, *args, **kwargs):
        return asyncreq(self.proxy, HANDLE_CALL, args, tuple(kwargs.items()))

    def __repr__(self):
        return f"async_({self.proxy!r})"


_async_proxies_cache = WeakValueDict()


def async_(proxy):
    """
    Returns an asynchronous "version" of the given proxy. Invoking the returned
    proxy will not block; instead it will return an
    :class:`rpyc.core.async_.AsyncResult` object that you can test for completion

    :param proxy: any **callable** RPyC proxy

    :returns: the proxy, wrapped by an asynchronous wrapper

    Example::

        async_sleep = rpyc.async_(conn.modules.time.sleep)
        res = async_sleep(5)

    .. _async_note:

    .. note::
       In order to avoid overloading the GC, the returned asynchronous wrapper is
       cached as a weak reference. Therefore, do not use::

           rpyc.async_(foo)(5)

       Always store the returned asynchronous wrapper in a variable, e.g. ::

           a_foo = rpyc.async_(foo)
           a_foo(5)

    .. note::
        Furthermore, async requests provide **no guarantee on execution
        order**. In particular, multiple subsequent async requests may be
        executed in reverse order.
    """
    pid = id(proxy)
    if pid in _async_proxies_cache:
        return _async_proxies_cache[pid]
    if not hasattr(proxy, "____conn__") or not hasattr(proxy, "____id_pack__"):
        raise TypeError(f"'proxy' must be a Netref: {proxy!r}")
    if not callable(proxy):
        raise TypeError(f"'proxy' must be callable: {proxy!r}")
    caller = _Async(proxy)
    _async_proxies_cache[id(caller)] = _async_proxies_cache[pid] = caller
    return caller


async_.__doc__ = _Async.__doc__
globals()['async'] = async_         # backward compatibility alias


class timed(object):
    """Creates a timed asynchronous proxy. Invoking the timed proxy will
    run in the background and will raise an :class:`rpyc.core.async_.AsyncResultTimeout`
    exception if the computation does not terminate within the given time frame

    :param proxy: any **callable** RPyC proxy
    :param timeout: the maximal number of seconds to allow the operation to run

    :returns: a ``timed`` wrapped proxy

    Example::

        t_sleep = rpyc.timed(conn.modules.time.sleep, 6) # allow up to 6 seconds
        t_sleep(4) # okay
        t_sleep(8) # will time out and raise AsyncResultTimeout
    """

    __slots__ = ("__weakref__", "proxy", "timeout")

    def __init__(self, proxy, timeout):
        self.proxy = async_(proxy)
        self.timeout = timeout

    def __call__(self, *args, **kwargs):
        res = self.proxy(*args, **kwargs)
        res.set_expiry(self.timeout)
        return res

    def __repr__(self):
        return f"timed({self.proxy.proxy!r}, {self.timeout!r})"


class BgServingThread(object):
    """Runs an RPyC server in the background to serve all requests and replies
    that arrive on the given RPyC connection. The thread is started upon the
    the instantiation of the ``BgServingThread`` object; you can use the
    :meth:`stop` method to stop the server thread.

    CAVEAT: RPyC defaults to bind_threads as False. So, there is no guarantee that the
    background thread will serve the request. See issue #522 for an example of this behavior.
    As the bind_threads feature matures, we may change the default to to True in the future.

    Example::

        conn = rpyc.connect(...)
        bg_server = BgServingThread(conn)
        ...
        bg_server.stop()

    .. note::
       For a more detailed explanation of asynchronous operation and the role of the
       ``BgServingThread``, see :ref:`tut5`

    """
    # these numbers are magical...
    SERVE_INTERVAL = 0.0
    SLEEP_INTERVAL = 0.1

    def __init__(self, conn, callback=None, serve_interval=SERVE_INTERVAL, sleep_interval=SLEEP_INTERVAL):
        self._conn = conn
        self._active = True
        self._callback = callback
        self._serve_interval = serve_interval
        self._sleep_interval = sleep_interval
        self._thread = worker(self._bg_server)

    def __del__(self):
        if self._active:
            self.stop()

    def _bg_server(self):
        try:
            while self._active:
                self._conn.serve(self._serve_interval)
                time.sleep(self._sleep_interval)  # to reduce contention
        except Exception:
            if self._active:
                self._active = False
                if self._callback is None:
                    raise
                self._callback()

    def stop(self):
        """stop the server thread. once stopped, it cannot be resumed. you will
        have to create a new BgServingThread object later."""
        assert self._active
        self._active = False
        self._thread.join()
        self._conn = None


def classpartial(*args, **kwargs):
    """Bind arguments to a class's __init__."""
    cls, args = args[0], args[1:]

    class Partial(cls):
        __doc__ = cls.__doc__

        def __new__(self):
            return cls(*args, **kwargs)
    Partial.__name__ = cls.__name__
    return Partial
