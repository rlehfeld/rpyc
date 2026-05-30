"""The RPyC protocol
"""
import sys
import inspect
import itertools
import socket

import collections
import os
import threading

from weakref import ref, WeakSet
from rpyc.lib import worker, spawn, Timeout, get_methods, get_id_pack, hasattr_static, ObjectType
from rpyc.lib.compat import pickle, next, maxint, select_error
from rpyc.lib.colls import WeakValueDict, RefCountingColl
from rpyc.core import consts, brine, vinegar, netref
from rpyc.core.async_ import AsyncResult


class PingError(Exception):
    """The exception raised should :func:`Connection.ping` fail"""
    pass


UNBOUND_THREAD_ID = 0  # Used when the message is being sent but the thread is not bound yet.
DEFAULT_CONFIG = dict(
    # ATTRIBUTES
    allow_safe_attrs=True,
    allow_exposed_attrs=True,
    allow_public_attrs=False,
    allow_all_attrs=False,
    safe_attrs=set(['__abs__', '__add__', '__and__', '__bool__', '__cmp__', '__contains__',
                    '__delitem__', '__delslice__', '__div__', '__divmod__', '__doc__',
                    '__eq__', '__float__', '__floordiv__', '__ge__', '__getitem__',
                    '__getslice__', '__gt__', '__hash__', '__hex__', '__iadd__', '__iand__',
                    '__idiv__', '__ifloordiv__', '__ilshift__', '__imod__', '__imul__',
                    '__index__', '__int__', '__invert__', '__ior__', '__ipow__', '__irshift__',
                    '__isub__', '__iter__', '__itruediv__', '__ixor__', '__le__', '__len__',
                    '__long__', '__lshift__', '__lt__', '__mod__', '__mul__', '__ne__',
                    '__neg__', '__new__', '__nonzero__', '__oct__', '__or__', '__pos__',
                    '__pow__', '__radd__', '__rand__', '__rdiv__', '__rdivmod__', '__repr__',
                    '__rfloordiv__', '__rlshift__', '__rmod__', '__rmul__', '__ror__',
                    '__rpow__', '__rrshift__', '__rshift__', '__rsub__', '__rtruediv__',
                    '__rxor__', '__setitem__', '__setslice__', '__str__', '__sub__',
                    '__truediv__', '__xor__', 'next', '__length_hint__', '__enter__',
                    '__exit__', '__next__', '__format__']),
    exposed_prefix="exposed_",
    allow_getattr=True,
    allow_setattr=False,
    allow_delattr=False,
    # EXCEPTIONS
    include_local_traceback=True,
    include_local_version=True,
    instantiate_custom_exceptions=False,
    import_custom_exceptions=False,
    instantiate_oldstyle_exceptions=False,  # which don't derive from Exception
    propagate_SystemExit_locally=False,  # whether to propagate SystemExit locally or to the other party
    propagate_KeyboardInterrupt_locally=True,  # whether to propagate KeyboardInterrupt locally or to the other party
    log_exceptions=True,
    # MISC
    allow_pickle=False,
    connid=None,
    credentials=None,
    endpoints=None,
    logger=None,
    sync_request_timeout=30,
    before_closed=None,
    close_catchall=False,
    bind_threads=os.environ.get('RPYC_BIND_THREADS', 'false').lower() == 'true',
)
"""
The default configuration dictionary of the protocol. You can override these parameters
by passing a different configuration dict to the :class:`Connection` class.

.. note::
   You only need to override the parameters you want to change. There's no need
   to repeat parameters whose values remain unchanged.

=======================================  ================  =====================================================
Parameter                                Default value     Description
=======================================  ================  =====================================================
``allow_safe_attrs``                     ``True``          Whether to allow the use of *safe* attributes
                                                           (only those listed as ``safe_attrs``)
``allow_exposed_attrs``                  ``True``          Whether to allow exposed attributes
                                                           (attributes that start with the ``exposed_prefix``)
``allow_public_attrs``                   ``False``         Whether to allow public attributes
                                                           (attributes that don't start with ``_``)
``allow_all_attrs``                      ``False``         Whether to allow all attributes (including private)
``safe_attrs``                           ``set([...])``    The set of attributes considered safe
``exposed_prefix``                       ``"exposed_"``    The prefix of exposed attributes
``allow_getattr``                        ``True``          Whether to allow getting of attributes (``getattr``)
``allow_setattr``                        ``False``         Whether to allow setting of attributes (``setattr``)
``allow_delattr``                        ``False``         Whether to allow deletion of attributes (``delattr``)
``allow_pickle``                         ``False``         Whether to allow the use of ``pickle``

``include_local_traceback``              ``True``          Whether to include the local traceback
                                                           in the remote exception
``instantiate_custom_exceptions``        ``False``         Whether to allow instantiation of
                                                           custom exceptions (not the built in ones)
``import_custom_exceptions``             ``False``         Whether to allow importing of
                                                           exceptions from not-yet-imported modules
``instantiate_oldstyle_exceptions``      ``False``         Whether to allow instantiation of exceptions
                                                           which don't derive from ``Exception``. This
                                                           is not applicable for Python 3 and later.
``propagate_SystemExit_locally``         ``False``         Whether to propagate ``SystemExit``
                                                           locally (kill the server) or to the other
                                                           party (kill the client)
``propagate_KeyboardInterrupt_locally``  ``False``         Whether to propagate ``KeyboardInterrupt``
                                                           locally (kill the server) or to the other
                                                           party (kill the client)
``logger``                               ``None``          The logger instance to use to log exceptions
                                                           (before they are sent to the other party)
                                                           and other events. If ``None``, no logging takes place.

``connid``                               ``None``          **Runtime**: the RPyC connection ID (used
                                                           mainly for debugging purposes)
``credentials``                          ``None``          **Runtime**: the credentials object that was returned
                                                           by the server's :ref:`authenticator <api-authenticators>`
                                                           or ``None``
``endpoints``                            ``None``          **Runtime**: The connection's endpoints. This is a tuple
                                                           made of the local socket endpoint (``getsockname``) and the
                                                           remote one (``getpeername``). This is set by the server
                                                           upon accepting a connection; client side connections
                                                           do no have this configuration option set.

``sync_request_timeout``                 ``30``            Default timeout for waiting results
``bind_threads``                         ``False``         Whether to restrict request/reply by thread (experimental).
                                                           The default value is False. Setting the environment variable
                                                           `RPYC_BIND_THREADS` to `"true"` will enable this feature.
=======================================  ================  =====================================================
"""


_connection_id_generator = itertools.count(1)


class Connection:
    """The RPyC *connection* (AKA *protocol*).

    Objects referenced over the connection are either local or remote. This class retains a strong reference to
    local objects that is deleted when the reference count is zero. Remote/proxied objects have a life-cycle
    controlled by a different address space. Since garbage collection is handled on the remote end, a weak reference
    is used for netrefs.

    :param root: the :class:`~rpyc.core.service.Service` object to expose
    :param channel: the :class:`~rpyc.core.channel.Channel` over which messages are passed
    :param config: the connection's configuration dict (overriding parameters
                   from the :data:`default configuration <DEFAULT_CONFIG>`)
    """
    __current = threading.local()
    __connections = WeakSet()

    def __init__(self, root, channel, config={}):
        self.__connections.add(self)
        self.__closed = True
        self._config = DEFAULT_CONFIG.copy()
        self._config.update(config)
        if self._config["connid"] is None:
            self._config["connid"] = f"conn{next(_connection_id_generator)}"

        self.__HANDLERS = self.__request_handlers()
        self.__channel = channel
        self.__seqcounter = itertools.count()
        self.__recv_event = threading.Condition(threading.Lock())
        # self.__send_event must use a re-entrant lock as __send might be
        # called from garbage collection and thus can be called while having lock
        self.__send_event = threading.Condition(threading.RLock())
        self._receiving = False
        self.__send_queue = []
        self.__send_loop = True
        self.__send_worker = worker(self.__send_thread)
        self.__request_callbacks = {}
        self.__local_objects = RefCountingColl()
        self.__last_traceback = None
        self.__proxy_cache = WeakValueDict()
        self.__netref_classes_cache = {}
        self.__remote_root = None
        self.__local_root = root
        self.__closed = False
        # Settings for bind_threads
        self.__bind_threads = self._config['bind_threads']
        self._threads = None
        if self.__bind_threads:
            # self._lock must use a re-entrant lock as __send and __cleanup
            # called from garbage collection and thus can be called while having lock
            self._lock = threading.RLock()
            self._threads = {}
            self._thread_pool = []
            self.__worker_pool = set()
            self.__cleaning_thread = None

    def stop_sending(self):
        with self.__send_event:
            send_worker = self.__send_worker
            self.__send_worker = None
            self.__send_loop = False
            self.__send_event.notify()
        if send_worker is not None:
            send_worker.join()

    @classmethod
    def stop_connections(cls):
        for conn in cls.__connections:
            conn.stop_sending()

    def __del__(self):
        # this is called from garbage collection
        # garbage collection might kick in at any moment
        # Therefore we must be very careful what we call
        # from here
        self.close()
        if self.__bind_threads:
            with self._lock:
                cleaning_thread = self.__cleaning_thread
                self.__cleaning_thread = None
            if cleaning_thread is threading.current_thread():
                spawn(cleaning_thread.join)
            elif cleaning_thread is not None:
                cleaning_thread.join()

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.close()

    def __repr__(self):
        a, b = object.__repr__(self).split(" object ")
        return f"{a} {self._config['connid']!r} object {b}"

    def __send_thread(self):
        def predicate():
            return not self.__send_loop or len(self.__send_queue) > 0

        with self.__send_event:
            exc = None
            while True:
                while self.__send_queue:
                    seq, data = self.__send_queue.pop(0)
                    self.__send_event.release()
                    if exc is None:
                        try:
                            self.__channel.send(data)
                        except BaseException as e:
                            exc = e
                    try:
                        if exc is not None:
                            self.__seq_request_callback(exc, seq, True, exc)
                            self.notify()
                    finally:
                        self.__send_event.acquire()

                if not self.__send_loop or exc is not None:
                    break

                self.__send_event.wait_for(predicate)

            if exc is not None:
                self.__send_loop = False

    def __cleanup(self, _anyway=True):  # IO
        if self.__closed and not _anyway:
            return
        self.__closed = True
        self.__channel.close()
        self.__local_root.on_disconnect(self)
        self.stop_sending()
        self.__request_callbacks.clear()
        self.__local_objects.clear()
        self.__proxy_cache.clear()
        self.__netref_classes_cache.clear()
        self.__last_traceback = None
        self.__remote_root = None
        self.__local_root = None
        # self.__seqcounter = None
        # self._config.clear()
        del self.__HANDLERS
        self.__cleanup_threads()

    def __cleanup_threads(self):
        if self.__bind_threads:
            with self._lock:
                if threading.current_thread() in self.__worker_pool:
                    if self.__cleaning_thread is None:
                        self.__cleaning_thread = worker(
                            self.__cleanup_threads
                        )
                    return

                with _ReceivingGuard(self):
                    worker_pool = self.__worker_pool
                    self.__worker_pool = set()

                    for thd in worker_pool:
                        thread = self.__get_thread(thd)
                        if thread:
                            thread.serve = False

            for thd in worker_pool:
                thd.join()

    def close(self):  # IO
        """closes the connection, releasing all held resources"""
        if self.__closed:
            return
        try:
            self.__closed = True
            if self._config.get("before_closed"):
                self._config["before_closed"](self.root)
            # TODO: define invariants/expectations around close sequence and timing
            self.sync_request(consts.HANDLE_CLOSE)
        except (EOFError, TimeoutError):
            pass
        except Exception:
            if not self._config["close_catchall"]:
                raise
        finally:
            self.__cleanup(_anyway=True)

    @property
    def closed(self):  # IO
        """Indicates whether the connection has been closed or not"""
        return self.__closed

    def fileno(self):  # IO
        """Returns the connectin's underlying file descriptor"""
        return self.__channel.fileno()

    def ping(self, data=None, timeout=3):  # IO
        """Asserts that the other party is functioning properly, by making sure
        the *data* is echoed back before the *timeout* expires

        :param data: the data to send (leave ``None`` for the default buffer)
        :param timeout: the maximal time to wait for echo

        :raises: :class:`PingError` if the echoed data does not match
        :raises: :class:`EOFError` if the remote host closes the connection
        """
        if data is None:
            data = "abcdefghijklmnopqrstuvwxyz" * 20
        res = self.async_request(consts.HANDLE_PING, data, timeout=timeout)
        if res.value != data:
            raise PingError("echo mismatches sent data")

    def __get_seq_id(self):  # IO
        return next(self.__seqcounter)

    def __send(self, msg, seq, args):  # IO
        data = brine.I1.pack(msg) + brine.dump((seq, args))  # see _dispatch
        if self.__bind_threads:
            with self._lock:
                this_thread = self.__get_thread()
                data = brine.I8I8.pack(this_thread.tid, this_thread._remote_thread_id) + data
                if msg == consts.MSG_REQUEST:
                    this_thread.incr()
                else:
                    this_thread.decr()

        with self.__send_event:
            if not self.__send_loop:
                if any(threading.current_thread() is con.__send_worker for con in self.__connections):
                    # can only cone here in case garbage collection was
                    # run by one of the send worker threads
                    return
                raise EOFError()
            self.__send_queue.append((seq, data))
            self.__send_event.notify()

    def __box(self, obj):  # boxing
        """store a local object in such a way that it could be recreated on
        the remote party either by-value or by-reference"""
        if brine.dumpable(obj):
            return consts.LABEL_VALUE, obj
        if type(obj) is tuple:
            return consts.LABEL_TUPLE, tuple(self.__box(item) for item in obj)
        if (isinstance(obj, netref.BaseNetref) or type(obj) is netref.NetrefMetaclass) and obj.____conn__ is self:
            return consts.LABEL_LOCAL_REF, obj.____id_pack__
        id_pack = get_id_pack(obj)
        self.__local_objects.add(id_pack, obj)
        return consts.LABEL_REMOTE_REF, id_pack

    def __unbox(self, package):  # boxing
        """recreate a local object representation of the remote object: if the
        object is passed by value, just return it; if the object is passed by
        reference, create a netref to it"""
        label, value = package
        if label == consts.LABEL_VALUE:
            return value
        if label == consts.LABEL_TUPLE:
            return tuple(self.__unbox(item) for item in value)
        if label == consts.LABEL_LOCAL_REF:
            return self.__local_objects[value]
        if label == consts.LABEL_REMOTE_REF:
            id_pack = (str(value[0]), value[1], value[2], value[3])  # so value is a id_pack
            proxy = self.__proxy_cache.get(id_pack)  # Ensure referents exist until we increment refcount issue #558
            if proxy is not None:
                proxy.____refcount__ += 1  # if cached then remote incremented refcount, so sync refcount
            else:
                proxy = self.__netref_factory(id_pack)
                self.__proxy_cache[id_pack] = proxy
            return proxy
        raise ValueError(f"invalid label {label!r}")

    def __netref_factory(self, id_pack):  # boxing
        """id_pack is for remote, so when class id fails to directly match """
        cls_id_pack = (id_pack[1], 0, ObjectType.CLASS.value)
        if cls_id_pack in self.__netref_classes_cache:
            cls = self.__netref_classes_cache[cls_id_pack]
            if id_pack[1:] == cls_id_pack:
                return cls
        elif id_pack[1:] != cls_id_pack:
            cls = self.sync_request(consts.HANDLE_TYPE, id_pack)
        else:
            # id_pack == cls_id_pack case
            # in the future, it could see if a sys.module cache/lookup hits first
            cls_methods = self.sync_request(consts.HANDLE_INSPECT, id_pack)
            cls = netref.class_factory(id_pack, cls_methods, self)
            self.__netref_classes_cache[cls_id_pack] = cls
            return cls
        return cls.____bind_instance__(self, id_pack)

    @classmethod
    def current(cls):
        return getattr(cls.__current, 'connection', None)

    def __dispatch_request(self, seq, raw_args):  # dispatch
        try:
            handler, args = raw_args
            args = self.__unbox(args)
            previous = getattr(self.__current, 'connection', None)
            self.__current.connection = self
            try:
                res = self.__HANDLERS[handler](self, *args)
            finally:
                if previous is None:
                    del self.__current.connection
                else:
                    self.__current.connection = previous

        except BaseException:
            # need to catch old style exceptions too
            t, v, tb = sys.exc_info()
            self.__last_traceback = tb
            logger = self._config["logger"]
            if logger and t is not StopIteration:
                logger.debug("Exception caught", exc_info=True)
            if t is SystemExit and self._config["propagate_SystemExit_locally"]:
                raise
            if t is KeyboardInterrupt and self._config["propagate_KeyboardInterrupt_locally"]:
                raise
            self.__send(consts.MSG_EXCEPTION, seq, self._box_exc(t, v, tb))
        else:
            self.__send(consts.MSG_REPLY, seq, self.__box(res))

    def _box_exc(self, typ, val, tb):  # dispatch?
        return vinegar.dump(typ, val, tb,
                            include_local_traceback=self._config["include_local_traceback"],
                            include_local_version=self._config["include_local_version"])

    def _unbox_exc(self, raw):  # dispatch?
        return vinegar.load(raw,
                            import_custom_exceptions=self._config["import_custom_exceptions"],
                            instantiate_custom_exceptions=self._config["instantiate_custom_exceptions"],
                            instantiate_oldstyle_exceptions=self._config["instantiate_oldstyle_exceptions"])

    def __seq_request_callback(self, msg, seq, is_exc, obj):
        unset = object()
        _callback = self.__request_callbacks.pop(seq, unset)
        if _callback is unset:
            if self._config["logger"] is not None:
                debug_msg = 'Received {} seq {} and a related request callback did not exist'
                self._config["logger"].debug(debug_msg.format(msg, seq))
        elif _callback is not None:
            _callback(is_exc, obj)

    def __dispatch(self, data):  # serving---dispatch?
        msg, = brine.I1.unpack(data[:1])  # unpack just msg to minimize time to release
        if msg == consts.MSG_REQUEST:
            if self.__bind_threads:
                with self._lock:
                    self.__get_thread().incr()
            seq, args = brine.load(data[1:])
            self.__dispatch_request(seq, args)
        else:
            if self.__bind_threads:
                with self._lock:
                    self.__get_thread().decr()

            if msg == consts.MSG_REPLY:
                seq, args = brine.load(data[1:])
                obj = self.__unbox(args)
                self.__seq_request_callback(msg, seq, False, obj)
                self.notify()
            elif msg == consts.MSG_EXCEPTION:
                seq, args = brine.load(data[1:])
                obj = self._unbox_exc(args)
                self.__seq_request_callback(msg, seq, True, obj)
                self.notify()
            else:
                raise ValueError(f"invalid message type: {msg!r}, {data=!r}")

    def notify(self):
        self.__channel.notify()

        if self.__bind_threads:
            self.__notify_bound()
        else:
            with self.__recv_event:
                self.__recv_event.notify_all()

    def __notify_bound(self):
        with self._lock:
            for thread in self._threads.values():
                thread[1]._condition.notify()

    def serve(self, timeout=1, wait_for_lock=True, predicate=None):  # serving
        """Serves a single request or reply that arrives within the given
        time frame (default is 1 sec). Note that the dispatching of a request
        might trigger multiple (nested) requests, thus this function may be
        reentrant.

        :returns: ``True`` if a request or reply were received, ``False`` otherwise.
        """
        timeout = Timeout(timeout)
        if self.__bind_threads:
            return self.__serve_bound(timeout, wait_for_lock, predicate)

        predicate_result = False

        def can_receive_or_predicate():
            nonlocal predicate_result
            predicate_result = predicate is not None and predicate()
            return not self._receiving or predicate_result

        with self.__recv_event:
            success = can_receive_or_predicate()
            if predicate_result:
                return False
            if not success:
                if not wait_for_lock:
                    return False
                success = self.__recv_event.wait_for(can_receive_or_predicate, timeout.timeleft())
                if not success or predicate_result:
                    return False
            self._receiving = True

        exc = None

        try:
            data = self.__channel.poll(timeout, predicate) and self.__channel.recv()
        except EOFError as e:
            exc = e
        finally:
            with self.__recv_event:
                self._receiving = False
                self.__recv_event.notify_all()

        if exc is not None:
            self.close()  # sends close async request
            raise exc from None

        if data:
            self.__dispatch(data)  # Dispatch will unbox, invoke callbacks, etc.
            return True
        return False

    def __serve_bound(self, timeout, wait_for_lock, predicate):
        """Serves messages like `serve` with the added benefit of making request/reply thread bound.
        - Experimental functionality `RPYC_BIND_THREADS`

        The first 8 bytes indicate the sending thread ID and intended recipient ID. When the recipient
        thread ID is not the thread that received the data, the remote thread ID and message are appended
        to the intended threads `_deque` and `_event` is set.

        :returns: ``True`` if a request or reply were received, ``False`` otherwise.
        """
        message_available = False
        predicate_result = False
        try:
            with self._lock:
                this_thread = self.__get_thread()

                def isready_or_predicate():
                    nonlocal message_available
                    nonlocal predicate_result
                    message_available = bool(this_thread._deque)
                    predicate_result = predicate is not None and predicate()
                    return message_available or not self._receiving or predicate_result

                ready = isready_or_predicate()
                if not ready and wait_for_lock:
                    self._thread_pool.append(this_thread)  # enter pool
                    ready = this_thread._condition.wait_for(isready_or_predicate, timeout=timeout.timeleft())
                    self._thread_pool.remove(this_thread)  # leave pool

                if not ready or predicate_result:
                    # timeout or not wait_for_lock or predicate
                    return False

                if message_available:
                    top = this_thread._deque.popleft()
                    if top is None:
                        return False
                    remote_thread_id, message = top
                else:
                    with _ReceivingGuard(self) as receiver:
                        while receiver:
                            # from upstream
                            if not this_thread.serve:
                                return False

                            self._lock.release()
                            try:
                                message = self.__channel.poll(timeout, predicate) and self.__channel.recv()
                            finally:
                                self._lock.acquire()

                            if not message:  # timeout or predicate
                                return False

                            remote_thread_id, local_thread_id = brine.I8I8.unpack(message[:16])
                            message = message[16:]

                            new = False

                            if local_thread_id == UNBOUND_THREAD_ID and this_thread._occupation_count != 0:
                                # Message is not meant for this thread. Use a thread that is not occupied
                                # or have the pool create a new one. Occupation count for threads in
                                # thread_pool can be trusted
                                new = True
                                for thread in self._thread_pool:
                                    if thread.serve and thread._occupation_count == 0 and not thread._deque:
                                        new = False
                                        break

                            elif local_thread_id in {UNBOUND_THREAD_ID, this_thread.tid}:
                                # Of course, the message is for this thread if equal. When id is UNBOUND_THREAD_ID,
                                # we deduce that occupation count is 0 from the previous if condition.
                                break
                            else:
                                # Otherwise, message was meant for another thread.
                                thread = self.__get_thread(tid=local_thread_id)
                                if not thread or not thread.serve:
                                    # bound thread terminated already.
                                    new = True

                            if new:
                                if not self.__closed:
                                    thd = worker(self.__serve_worker)
                                    self.__worker_pool.add(thd)
                                    thread = self.__get_thread(thd, create=True)
                                else:
                                    thread = None

                            if thread:
                                thread._deque.append((remote_thread_id, message))
                                thread._condition.notify()

                this_thread._remote_thread_id = remote_thread_id

        except EOFError:
            self.close()  # sends close async request
            raise

        self.__dispatch(message)
        return True

    def __serve_worker(self):
        """Callable that is used to schedule serve as a new thread
        - Experimental functionality `RPYC_BIND_THREADS`

        :returns: None
        """
        with self._lock:
            thread = self.__get_thread()

            # from upstream
            try:
                while thread.loop:
                    self._lock.release()
                    try:
                        self.serve(None)
                    finally:
                        self._lock.acquire()

            except (socket.error, select_error, IOError):
                if not self.closed:
                    raise
            except EOFError:
                pass
            finally:
                thread.serve = False

    @staticmethod
    def __is_thread_alive(thd):
        # gevent does not properly implement in it's wrapper is_alive.
        # It causes an AttributeError
        # Consider thread to be alive in this case
        is_alive = thd.is_alive
        try:
            return is_alive()
        except AttributeError:
            return True

    def __get_thread(self, tid=None, *, create=None):
        """Get internal thread information for current thread for ID, when None use current thread.
        - Experimental functionality `RPYC_BIND_THREADS`

        :returns: _Thread
        """
        if isinstance(tid, threading.Thread):
            cthid = tid
            cid = tid.ident
            tid = cid
            if create is None:
                create = cthid is threading.current_thread()
        else:
            cthid = threading.current_thread()
            cid = cthid.ident
            if tid is None:
                tid = cid
            if create is None:
                create = tid == cid
            assert not create or cid == tid, (
                "create only supported for current thread or when thread object is given"
            )

        rthd, thread = self._threads.get(tid, (None, None))
        if rthd is not None:
            thd = rthd()
            if thd is None or not self.__is_thread_alive(thd):
                del rthd
                self._threads.pop(tid)
                thread = None
        if thread is None and create:
            rconnection = ref(self)

            def thread_deleted(_, tid=cid, rconnection=rconnection):
                connection = rconnection()
                if connection is not None:
                    with connection._lock:
                        connection._threads.pop(tid)

            thd = cthid
            rthd = ref(thd, thread_deleted)
            thread = _Thread(cid, self._lock)
            self._threads[cid] = rthd, thread

        return thread

    def poll(self, timeout=0):  # serving
        """Serves a single transaction, should one arrives in the given
        interval. Note that handling a request/reply may trigger nested
        requests, which are all part of a single transaction.

        :returns: ``True`` if a transaction was served, ``False`` otherwise"""
        return self.serve(timeout, False)

    def serve_all(self):  # serving
        """Serves all requests and replies for as long as the connection is
        alive."""
        try:
            while not self.closed:
                self.serve(None)
        except (socket.error, select_error, IOError):
            if not self.closed:
                raise
        except EOFError:
            pass
        finally:
            self.close()

    def serve_threaded(self, thread_count=10):  # serving
        """Serves all requests and replies for as long as the connection is alive.

        CAVEAT: using non-immutable types that require a netref to be constructed to serve a request,
        or invoking anything else that performs a sync_request, may timeout due to the sync_request reply being
        received by another thread serving the connection. A more conventional approach where each client thread
        opens a new connection would allow `ThreadedServer` to naturally avoid such multiplexing issues and
        is the preferred approach for threading procedures that invoke sync_request. See issue #345
        """
        def _thread_target():
            try:
                while True:
                    self.serve(None)
            except (socket.error, select_error, IOError):
                if not self.closed:
                    raise
            except EOFError:
                pass

        try:
            threads = [worker(_thread_target)
                       for _ in range(thread_count)]

            for thread in threads:
                thread.join()
        finally:
            self.close()

    def poll_all(self, timeout=0):  # serving
        """Serves all requests and replies that arrive within the given interval.

        :returns: ``True`` if at least a single transaction was served, ``False`` otherwise
        """
        at_least_once = False
        timeout = Timeout(timeout)
        try:
            while True:
                if self.poll(timeout):
                    at_least_once = True
                if timeout.expired():
                    break
        except EOFError:
            pass
        return at_least_once

    def sync_request(self, handler, *args):
        """requests, sends a synchronous request (waits for the reply to arrive)

        :raises: any exception that the requests may be generated
        :returns: the result of the request
        """
        timeout = self._config["sync_request_timeout"]
        _async_res = self.async_request(handler, *args, timeout=timeout)
        # _async_res is an instance of AsyncResult, the value property invokes Connection.serve via AsyncResult.wait
        return _async_res.value

    def __async_request(self, handler, args=(), callback=None):  # serving
        seq = self.__get_seq_id()
        self.__request_callbacks[seq] = callback
        try:
            self.__send(consts.MSG_REQUEST, seq, (handler, self.__box(args)))
        except Exception:
            # TODO: review test_remote_exception, logging exceptions show attempt to write on closed stream
            # depending on the case, the MSG_REQUEST may or may not have been sent completely
            # so, pop the callback and raise to keep response integrity is consistent
            self.__request_callbacks.pop(seq, None)
            raise

    def async_request(self, handler, *args, **kwargs):  # serving
        """Send an asynchronous request (does not wait for it to finish)

        :returns: an :class:`rpyc.core.async_.AsyncResult` object, which will
                  eventually hold the result (or exception)
        """
        timeout = kwargs.pop("timeout", None)
        if kwargs:
            raise TypeError("got unexpected keyword argument(s) {list(kwargs.keys()}")
        res = AsyncResult(self)
        if timeout is not None:
            res.set_expiry(timeout)
        self.__async_request(handler, args, res)
        return res

    @property
    def root(self):  # serving
        """Fetches the root object (service) of the other party"""
        if self.__remote_root is None:
            self.__remote_root = self.sync_request(consts.HANDLE_GETROOT)
        return self.__remote_root

    @property
    def local_root(self):
        return self.__handle_getroot()

    def __check_attr(self, obj, name, perm):  # attribute access
        config = self._config
        if not config[perm]:
            raise AttributeError(f"cannot access {name!r}")
        prefix = config["allow_exposed_attrs"] and config["exposed_prefix"]
        plain = any(
            (
                config["allow_all_attrs"],
                config["allow_exposed_attrs"] and name.startswith(prefix),
                config["allow_safe_attrs"] and name in config["safe_attrs"],
                config["allow_public_attrs"] and not name.startswith("_"),
            )
        )
        has_exposed = (
            prefix and not name.startswith(prefix) and
            (hasattr(obj, prefix + name) or hasattr_static(obj, prefix + name))
        )
        if plain and (not has_exposed or hasattr(obj, name)):
            return name
        if has_exposed:
            return prefix + name
        if plain:
            return name  # chance for better traceback
        raise AttributeError(f"cannot access {name!r}")

    def __access_attr(self, obj, name, args, overrider, param, default):  # attribute access
        if type(name) is bytes:
            name = str(name, "utf8")
        elif type(name) is not str:
            raise TypeError("name must be a string")
        accessor = getattr(obj, overrider, None)
        if accessor is None:
            name = self.__check_attr(obj, name, param)
            return default(obj, name, *args)
        if inspect.isclass(obj):
            getter = getattr(accessor, '__get__', None)
            if getter is not None:
                accessor = getter(obj, obj)
        return accessor(name, *args)

    @classmethod
    def __request_handlers(cls):  # request handlers
        return {
            consts.HANDLE_PING: cls.__handle_ping,
            consts.HANDLE_CLOSE: cls.__handle_close,
            consts.HANDLE_GETROOT: cls.__handle_getroot,
            consts.HANDLE_GETATTR: cls.__handle_getattr,
            consts.HANDLE_DELATTR: cls.__handle_delattr,
            consts.HANDLE_SETATTR: cls.__handle_setattr,
            consts.HANDLE_CALL: cls.__handle_call,
            consts.HANDLE_REPR: cls.__handle_repr,
            consts.HANDLE_STR: cls.__handle_str,
            consts.HANDLE_BOOL: cls.__handle_bool,
            consts.HANDLE_CMP: cls.__handle_cmp,
            consts.HANDLE_HASH: cls.__handle_hash,
            consts.HANDLE_TYPE: cls.__handle_type,
            consts.HANDLE_INSTANCECHECK: cls.__handle_instancecheck,
            consts.HANDLE_SUBCLASSCHECK: cls.__handle_subclasscheck,
            consts.HANDLE_DIR: cls.__handle_dir,
            consts.HANDLE_PICKLE: cls.__handle_pickle,
            consts.HANDLE_DEL: cls.__handle_del,
            consts.HANDLE_INSPECT: cls.__handle_inspect,
            consts.HANDLE_BUFFITER: cls.__handle_buffiter,
            consts.HANDLE_OLDSLICING: cls.__handle_oldslicing,
            consts.HANDLE_CTXEXIT: cls.__handle_ctxexit,
        }

    def __handle_ping(self, data):  # request handler
        return data

    def __handle_close(self):  # request handler
        self.__cleanup()

    def __handle_getroot(self):  # request handler
        return self.__local_root

    def __handle_del(self, id_pack, count):  # request handler
        self.__local_objects.decref(id_pack, count)

    def __handle_repr(self, obj):  # request handler
        return repr(obj)

    def __handle_str(self, obj):  # request handler
        return str(obj)

    def __handle_bool(self, obj):  # request handler
        return bool(obj)

    def __handle_cmp(self, obj, other, op='__cmp__'):  # request handler
        # cmp() might enter recursive resonance... so use the underlying type and return cmp(obj, other)
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            return conn.sync_req(consts.HANDLE_CMP, other, op)
        try:
            compare = self.__access_attr(obj, op, (), "_rpyc_getattr", "allow_getattr", getattr)
        except AttributeError:
            return NotImplemented
        return compare(other)

    def __handle_hash(self, obj):  # request handler
        return hash(obj)

    def __handle_call(self, obj, args, kwargs=()):  # request handler
        return obj(*args, **dict(kwargs))

    def __handle_dir(self, obj):  # request handler
        return tuple(dir(obj))

    def __handle_inspect(self, id_pack):  # request handler
        conn = getattr(self.__local_objects[id_pack], '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # When RPyC is chained (RPyC over RPyC), id_pack is cached in local objects as a netref
            # since __mro__ is not a safe attribute the request is forwarded using the proxy connection
            # see issue #346 or tests.test_rpyc_over_rpyc.Test_rpyc_over_rpyc
            return conn.sync_request(consts.HANDLE_INSPECT, id_pack)
        return tuple(get_methods(netref.LOCAL_ATTRS, self.__local_objects[id_pack]))

    def __handle_getattr(self, obj, name):  # request handler
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # When RPyC is chained (RPyC over RPyC)
            return conn.sync_request(consts.HANDLE_GETATTR, obj, name)
        return self.__access_attr(obj, name, (), "_rpyc_getattr", "allow_getattr", getattr)

    def __handle_delattr(self, obj, name):  # request handler
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # RPyC is chained (RPyC over RPyC)
            return conn.sync_request(consts.HANDLE_DELATTR, obj, name)
        return self.__access_attr(obj, name, (), "_rpyc_delattr", "allow_delattr", delattr)

    def __handle_setattr(self, obj, name, value):  # request handler
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # RPyC is chained (RPyC over RPyC)
            return conn.sync_request(consts.HANDLE_SETATTR, obj, name, value)
        return self.__access_attr(obj, name, (value,), "_rpyc_setattr", "allow_setattr", setattr)

    def __handle_ctxexit(self, obj, rawexc):  # request handler
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # RPyC is chained (RPyC over RPyC)
            return conn.sync_request(consts.HANDLE_CTXEXIT, obj, rawexc)

        if rawexc is None:
            typ = exc = tb = None
        else:
            exc = self._unbox_exc(rawexc)
            try:
                raise exc
            except BaseException:
                typ, exc, tb = sys.exc_info()
        return self.__handle_getattr(obj, "__exit__")(typ, exc, tb)

    def __handle_type(self, id_pack):  # request handler
        conn = getattr(self.__local_objects[id_pack], '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # When RPyC is chained (RPyC over RPyC), id_pack is cached in local objects as a netref
            # since __mro__ is not a safe attribute the request is forwarded using the proxy connection
            # see issue #346 or tests.test_rpyc_over_rpyc.Test_rpyc_over_rpyc
            return conn.sync_request(consts.HANDLE_TYPE, id_pack)
        return type(self.__local_objects[id_pack])

    def __handle_instancecheck(self, obj, other_id_pack):
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # When RPyC is chained (RPyC over RPyC), id_pack is cached in local objects as a netref
            # since __mro__ is not a safe attribute the request is forwarded using the proxy connection
            # relates to issue #346 or tests.test_netref_hierachy.Test_Netref_Hierarchy.test_StandardError
            return conn.sync_request(consts.HANDLE_INSTANCECHECK, obj, other_id_pack)
        try:
            other = self.__local_objects[other_id_pack]
        except KeyError:
            pass
        else:
            return isinstance(other, obj)

        # Create a name pack which would be familiar here and see if there is a hit
        other_id_pack2 = (other_id_pack[0], other_id_pack[1], 0)
        if other_id_pack[0] in netref.builtin_classes_cache:
            cls = netref.builtin_classes_cache[other_id_pack[0]]
            other = cls(self, other_id_pack)
        elif other_id_pack2 in self.__netref_classes_cache:
            cls = self.__netref_classes_cache[other_id_pack2]
            other = cls(self, other_id_pack)
        else:  # might just have missed cache, FIX ME
            return False
        return isinstance(other, obj)

    def __handle_subclasscheck(self, obj, other_id_pack):
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # When RPyC is chained (RPyC over RPyC), id_pack is cached in local objects as a netref
            # since __mro__ is not a safe attribute the request is forwarded using the proxy connection
            # relates to issue #346 or tests.test_netref_hierachy.Test_Netref_Hierarchy.test_StandardError
            return conn.sync_request(consts.HANDLE_SUBCLASSCHECK, obj, other_id_pack)

        try:
            other = self.__local_objects[other_id_pack]
        except KeyError:
            pass
        else:
            return isinstance(other, obj)

        # Create a name pack which would be familiar here and see if there is a hit
        other_id_pack2 = (other_id_pack[0], other_id_pack[1], 0)
        if other_id_pack[0] in netref.builtin_classes_cache:
            cls = netref.builtin_classes_cache[other_id_pack[0]]
            other = cls(self, other_id_pack)
        elif other_id_pack2 in self.__netref_classes_cache:
            cls = self.__netref_classes_cache[other_id_pack2]
            other = cls(self, other_id_pack)
        else:  # might just have missed cache, FIX ME
            return False
        return issubclass(other, obj)

    def __handle_pickle(self, obj, proto):  # request handler
        if not self._config["allow_pickle"]:
            raise ValueError("pickling is disabled")
        return bytes(pickle.dumps(obj, proto))

    def __handle_buffiter(self, obj, count):  # request handler
        return tuple(itertools.islice(obj, count))

    def __handle_oldslicing(self, obj, attempt, fallback, start, stop, args):  # request handler
        conn = getattr(obj, '____conn__', None)
        if conn is not None:  # keep unwrapping!
            # When RPyC is chained (RPyC over RPyC)
            return conn.sync_request(
                consts.HANDLE_OLDSLICING, obj, attempt, fallback, start, stop, args
            )

        try:
            # first try __xxxitem__
            getitem = self.__handle_getattr(obj, attempt)
            return getitem(slice(start, stop), *args)
        except Exception:
            # fallback to __xxxslice__. see issue #41
            if stop is None:
                stop = maxint
            getslice = self.__handle_getattr(obj, fallback)
            return getslice(start, stop, *args)


class _Thread:
    """Internal thread information for the RPYC protocol used for thread binding."""

    def __init__(self, tid, lock):
        super().__init__()

        self.tid = tid

        self._remote_thread_id = UNBOUND_THREAD_ID
        self._occupation_count = 0
        self.__serve = True
        self._condition = threading.Condition(lock)
        self._deque = collections.deque()

    @property
    def serve(self):
        return self.__serve

    @property
    def loop(self):
        return self.__serve or bool(self._deque)

    @serve.setter
    def serve(self, value):
        if value is False and self.__serve is True:
            self.__serve = False
            self._deque.append(None)
            self._condition.notify()

    def decr(self):
        if self._occupation_count <= 1:
            self._occupation_count = 0
            self._remote_thread_id = UNBOUND_THREAD_ID
        else:
            self._occupation_count -= 1

    def incr(self):
        self._occupation_count += 1


class _ReceivingGuard:
    def __init__(self, connection):
        self.__connection = connection

    def __bool__(self):
        return self.__receiver

    def __enter__(self):
        self.__receiver = not self.__connection._receiving
        if self.__receiver:
            self.__connection._receiving = True
        return self

    def __exit__(self, t, v, tb):
        if self.__receiver:
            self.__connection._receiving = False
            for thread in self.__connection._thread_pool:
                if not thread._deque:
                    thread._condition.notify()
                    break


# unfortunately there is no official interface to register cleanup / termination
# methods for non-daemon threads. Then use the unofficial one for the time being
threading._register_atexit(Connection.stop_connections)
