"""
An abstraction layer over OS-dependent file-like objects, that provides a
consistent view of a *duplex byte stream*.
"""
import sys
import io
import os
import socket
import errno
import threading
from rpyc.lib import safe_import, Timeout, worker, socket_backoff_connect
from rpyc.lib.compat import poll, select_error, BYTES_LITERAL, get_exc_errno
from rpyc.core.consts import STREAM_CHUNK
win32file = safe_import("win32file")
win32pipe = safe_import("win32pipe")
win32event = safe_import("win32event")
pywintypes = safe_import("pywintypes")
fcntl = safe_import("fcntl")
ssl = safe_import("ssl")


retry_errnos = (errno.EAGAIN, errno.EWOULDBLOCK)


if os.name == 'nt':
    def get_inheritable(channel):
        return os.get_handle_inheritable(channel.fileno())

    def set_inheritable(channel, inheritable):
        os.set_handle_inheritable(channel.fileno(), inheritable)
else:
    def get_inheritable(channel):
        return os.get_inheritable(channel.fileno())

    def set_inheritable(channel, inheritable):
        os.set_inheritable(channel.fileno(), inheritable)


class Stream:
    """Base Stream"""

    __slots__ = ('__socket_r', '__socket_w',
                 '__predicate',
                 '__cond', '__reading', '__polling', '__read_pause_depth',
                 '__listening')

    def __init__(self):
        self.__cond = threading.Condition(threading.Lock())
        self.__polling = False
        self.__reading = False
        self.__read_pause_depth = 0
        self.__listening = False
        self.__predicate = None

        self.__socket_w, self.__socket_r = socket.socketpair()
        self.__socket_r.set_inheritable(False)
        self.__socket_w.set_inheritable(False)
        if hasattr(socket, 'SHUT_WR'):
            self.__socket_r.shutdown(socket.SHUT_WR)
        if hasattr(socket, 'SHUT_RD'):
            self.__socket_w.shutdown(socket.SHUT_RD)

        if fcntl:
            fd = self.__socket_r.fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        else:
            self.__socket_r.setblocking(False)

    def close(self):
        """closes the stream, releasing any system resources associated with it"""
        def predicate():
            return not self.__listening

        with self.__cond:
            socket_w = self.__socket_w
            if socket_w is not None:
                self.__socket_w = None
                socket_r = self.__socket_r
                self.__socket_r = None
                if not predicate():
                    socket_w.send(b'C')
                    self.__cond.wait_for(predicate)
                if hasattr(socket, 'SHUT_RDWR'):
                    socket_w.shutdown(socket.SHUT_RDWR)
                socket_w.close()
                if hasattr(socket, 'SHUT_RDWR'):
                    socket_r.shutdown(socket.SHUT_RDWR)
                socket_r.close()

    @property
    def closed(self):
        """tests whether the stream is closed or not"""
        raise NotImplementedError()

    def fileno(self):
        """returns the stream's file descriptor"""
        raise NotImplementedError()

    def acquire_read(self):
        def predicate():
            return self.__read_pause_depth <= 0 and not self.__reading

        with self.__cond:
            self.__cond.wait_for(predicate)
            self.__reading = True

    def release_read(self):
        with self.__cond:
            if not self.__reading:
                raise RuntimeError('acquire_read not called before')
            self.__reading = False
            self.__cond.notify_all()

    def pause_read(self):
        def predicate():
            return not (self.__reading or self.__polling)

        with self.__cond:
            self.__read_pause_depth += 1
            if self.__polling and self.__socket_w is not None:
                self.__socket_w.send(b'P')
            self.__cond.wait_for(predicate)

    def resume_read(self):
        with self.__cond:
            if self.__read_pause_depth <= 0:
                raise RuntimeError('pause_write not called before')
            self.__read_pause_depth -= 1
            if self.__read_pause_depth == 0:
                self.__cond.notify_all()

    def notify(self):
        with self.__cond:
            if (self.__socket_w is not None and
                    self.__predicate is not None and
                    self.__predicate()):
                self.__socket_w.send(b'N')
            self.__cond.notify_all()

    def poll(self, timeout, predicate=None):
        """indicates whether the stream has data to read (within *timeout*
        seconds)"""

        timeout = Timeout(timeout)
        predicate_result = False

        def polling_or_predicate():
            nonlocal predicate_result
            predicate_result = (
                predicate is not None and
                predicate()
            )

            return (
                (self.__read_pause_depth <= 0 and
                 not self.__polling) or predicate_result
            )

        with self.__cond:
            result = self.__cond.wait_for(polling_or_predicate, timeout.timeleft())
            if not result or predicate_result:
                return False
            assert (
                self.__read_pause_depth <= 0 and
                not self.__polling
            ), f"unexpected state {(self.__read_pause_depth, self.__polling)=}"

            self.__polling = True
            self.__predicate = predicate
            socket_r = self.__socket_r
            self.__listening = socket_r is not None

        try:
            p = poll()   # from lib.compat, it may be a select object on non-Unix platforms
            sfd = self.fileno()
            if socket_r is not None:
                wfd = socket_r.fileno()
                p.register(wfd, "r")
            else:
                wfd = None
            p.register(sfd, "r")
            while True:
                try:
                    rl = p.poll(timeout.timeleft())
                except select_error as ex:
                    if ex.args[0] == errno.EINTR:
                        continue
                    else:
                        raise
                if wfd is not None and any(wfd == fd for fd, _ in rl):
                    try:
                        c = socket_r.recv(1)
                    except BlockingIOError:
                        # actually should never come here but seen together
                        # with gevent monkey patched poll on windows. So
                        # something is not working right here.
                        # Just ignore and continue for the moment
                        continue
                    except BaseException:
                        raise

                    if c == b'C':
                        # notification for socket closing
                        p.unregister(wfd)
                        socket_r = None
                        wfd = None
                        with self.__cond:
                            self.__listening = False
                            self.__cond.notify_all()
                        continue
                    return False

                return any(sfd == fd for fd, _ in rl)

        except ValueError as ex:
            # if the underlying call is a select(), then the following errors may happen:
            # - "ValueError: filedescriptor cannot be a negative integer (-1)"
            # - "ValueError: filedescriptor out of range in select()"
            # let's translate them to select.error
            raise select_error(str(ex))
        finally:
            with self.__cond:
                self.__predicate = None
                self.__polling = False
                self.__listening = False
                self.__cond.notify_all()

    def read(self, count):
        """reads **exactly** *count* bytes, or raise EOFError

        :param count: the number of bytes to read

        :returns: read data
        """
        raise NotImplementedError()

    def write(self, data):
        """writes the entire *data*, or raise EOFError

        :param data: a string of binary data
        """
        raise NotImplementedError()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


class ClosedFile:
    """Represents a closed file object (singleton)"""
    __slots__ = ()

    def __getattr__(self, name):
        if name.startswith("__"):  # issue 71
            raise AttributeError("stream has been closed")
        raise EOFError("stream has been closed")

    def close(self):
        pass

    def notify(self):
        pass

    @property
    def closed(self):
        return True

    def fileno(self):
        raise EOFError("stream has been closed")


ClosedFile = ClosedFile()


class SocketStream(Stream):
    """A stream over a socket"""

    __slots__ = ("sock",)
    MAX_IO_CHUNK = STREAM_CHUNK

    def __init__(self, sock):
        set_inheritable(sock, False)
        self.sock = sock
        super().__init__()

    @classmethod
    def _connect(cls, host, port, family=socket.AF_INET, socktype=socket.SOCK_STREAM,
                 proto=0, timeout=3, nodelay=True, keepalive=False, attempts=6):
        family, socktype, proto, _, sockaddr = socket.getaddrinfo(host, port, family,
                                                                  socktype, proto)[0]
        s = socket_backoff_connect(family, socktype, proto, sockaddr, timeout, attempts)
        try:
            if nodelay:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if keepalive:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                # Linux specific: after <keepalive> idle seconds, start sending keepalives every <keepalive> seconds.
                is_linux_socket = all(
                    (
                        hasattr(socket, "TCP_KEEPIDLE"),
                        hasattr(socket, "TCP_KEEPINTVL"),
                        hasattr(socket, "TCP_KEEPCNT"),
                    )
                )
                if is_linux_socket:
                    # Drop connection after 5 failed keepalives
                    # `keepalive` may be a bool or an integer
                    if keepalive is True:
                        keepalive = 60
                    if keepalive < 1:
                        raise ValueError("Keepalive minimal value is 1 second")

                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, keepalive)
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, keepalive)
            return s
        except BaseException:
            s.close()
            raise

    @classmethod
    def connect(cls, host, port, **kwargs):
        """factory method that creates a ``SocketStream`` over a socket connected
        to *host* and *port*

        :param host: the host name
        :param port: the TCP port
        :param family: specify a custom socket family
        :param socktype: specify a custom socket type
        :param proto: specify a custom socket protocol
        :param timeout: connection timeout (default is 3 seconds)
        :param nodelay: set the TCP_NODELAY socket option
        :param keepalive: enable TCP keepalives. The value should be a boolean,
                          but on Linux, it can also be an integer specifying the
                          keepalive interval (in seconds)
        :param ipv6: if True, creates an IPv6 socket (``AF_INET6``); otherwise
                     an IPv4 (``AF_INET``) socket is created

        :returns: a :class:`SocketStream`
        """
        if kwargs.pop("ipv6", False):
            kwargs["family"] = socket.AF_INET6
        return cls(cls._connect(host, port, **kwargs))

    @classmethod
    def unix_connect(cls, path, timeout=3):
        """factory method that creates a ``SocketStream`` over a unix domain socket
        located in *path*

        :param path: the path to the unix domain socket
        :param timeout: socket timeout
        """
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            s.connect(path)
            return cls(s)
        except BaseException:
            s.close()
            raise

    @classmethod
    def ssl_connect(cls, host, port, ssl_kwargs, **kwargs):
        """factory method that creates a ``SocketStream`` over an SSL-wrapped
        socket, connected to *host* and *port* with the given credentials.

        :param host: the host name
        :param port: the TCP port
        :param ssl_kwargs: a dictionary of keyword arguments for
                           ``ssl.SSLContext`` and ``ssl.SSLContext.wrap_socket``
        :param kwargs: additional keyword arguments: ``family``, ``socktype``,
                       ``proto``, ``timeout``, ``nodelay``, passed directly to
                       the ``socket`` constructor, or ``ipv6``.
        :param ipv6: if True, creates an IPv6 socket (``AF_INET6``); otherwise
                     an IPv4 (``AF_INET``) socket is created

        :returns: a :class:`SocketStream`
        """
        if kwargs.pop("ipv6", False):
            kwargs["family"] = socket.AF_INET6
        s = cls._connect(host, port, **kwargs)
        try:
            if "ssl_version" in ssl_kwargs:
                context = ssl.SSLContext(ssl_kwargs.pop("ssl_version"))
            else:
                context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            certfile = ssl_kwargs.pop("certfile", None)
            keyfile = ssl_kwargs.pop("keyfile", None)
            if certfile is not None:
                context.load_cert_chain(certfile, keyfile=keyfile)
            ca_certs = ssl_kwargs.pop("ca_certs", None)
            if ca_certs is not None:
                context.load_verify_locations(ca_certs)
            ciphers = ssl_kwargs.pop("ciphers", None)
            if ciphers is not None:
                context.set_ciphers(ciphers)
            check_hostname = ssl_kwargs.pop("check_hostname", None)
            if check_hostname is not None:
                context.check_hostname = check_hostname
            cert_reqs = ssl_kwargs.pop("cert_reqs", None)
            if cert_reqs is not None:
                context.verify_mode = cert_reqs
            s2 = context.wrap_socket(s, server_hostname=host, **ssl_kwargs)
            return cls(s2)
        except BaseException:
            s.close()
            raise

    @property
    def closed(self):
        return self.sock is ClosedFile

    def close(self):
        sock, self.sock = self.sock, ClosedFile
        if sock is not ClosedFile:
            if hasattr(socket, 'SHUT_WR'):
                try:
                    # inform peer that we are finished sending
                    sock.shutdown(socket.SHUT_WR)
                    while True:
                        # wait for peer to close it's sending side as well
                        try:
                            buf = sock.recv(self.MAX_IO_CHUNK)
                            if not buf:
                                break
                        except TimeoutError:
                            continue
                except Exception:
                    pass
            sock.close()
        super().close()

    def fileno(self):
        try:
            fileno = self.sock.fileno()
        except OSError as ex:
            self.close()
            if get_exc_errno(ex) == errno.EBADF:
                raise EOFError()
            else:
                raise
        if isinstance(fileno, int) and fileno == -1:
            raise EOFError("stream has been closed")

        return fileno

    def read(self, count):
        data = []
        while count > 0:
            # send and recv must not be done in parallel on TLS sockets
            self.acquire_read()
            try:
                buf = self.sock.recv(min(self.MAX_IO_CHUNK, count))
            except TimeoutError:
                continue
            except OSError as ex:
                if get_exc_errno(ex) in retry_errnos:
                    # windows just has to be a bitch
                    continue
                self.close()
                raise EOFError(ex)
            finally:
                self.release_read()
            if not buf:
                self.close()
                raise EOFError("connection closed by peer")
            data.append(buf)
            count -= len(buf)
        return BYTES_LITERAL("").join(data)

    def write(self, data):
        try:
            while data:
                # send and recv must not be done in parallel on TLS sockets
                self.pause_read()
                try:
                    count = self.sock.send(data[:self.MAX_IO_CHUNK])
                finally:
                    # resume reading
                    self.resume_read()
                data = data[count:]
        except OSError as ex:
            self.close()
            raise EOFError(ex)


class TunneledSocketStream(SocketStream):
    """A socket stream over an SSH tunnel (terminates the tunnel when the connection closes)"""

    __slots__ = ("__tun",)

    def __init__(self, sock):
        super().__init__(sock)
        self.tun = None

    def close(self):
        super().close()
        if self.tun:
            self.tun.close()

    @property
    def tun(self):
        return self.__tun

    @tun.setter
    def tun(self, value):
        if (value is not None and
                value is not ClosedFile and
                hasattr(value, 'fileno')):
            set_inheritable(value, False)
        self.__tun = value


class PipeStream(Stream):
    """A stream over two simplex pipes (one used to input, another for output)"""

    __slots__ = ("incoming", "outgoing", "__condition", "__ready", "__reader")
    MAX_IO_CHUNK = STREAM_CHUNK

    def __init__(self, incoming, outgoing):
        def rawstream(stream, mode):
            fileno = stream.fileno()
            try:
                stream.detach()
            except (AttributeError, io.UnsupportedOperation):
                return stream
            return open(fileno, mode, buffering=0)

        self.__redirect_inputs(incoming)
        self.__redirect_outputs(outgoing)
        outgoing.flush()
        rawincoming = rawstream(incoming, "rb")
        rawoutgoing = rawstream(outgoing, "wb")
        set_inheritable(rawincoming, False)
        set_inheritable(rawoutgoing, False)
        self.incoming = rawincoming
        self.outgoing = rawoutgoing
        self.__condition = threading.Condition(threading.Lock())
        self.__ready = BYTES_LITERAL("")
        self.__reader = worker(self.__readthread, rawincoming)

    @staticmethod
    def __redirect_inputs(stream):
        inputs = ('stdin', '__stdin__')
        newinput = None
        for attr in inputs:
            if getattr(sys, attr) is stream:
                if newinput is None:
                    newinput = open(os.devnull, "r")
                setattr(sys, attr, newinput)

    @staticmethod
    def __redirect_outputs(stream):
        outputs = ('stdout', '__stdout__', 'stderr', '__stderr__')
        newoutput = None
        for attr in outputs:
            if getattr(sys, attr) is stream:
                if newoutput is None:
                    newoutput = open(os.devnull, "w")
                setattr(sys, attr, newoutput)

    def __del__(self):
        # this is called from garbage collection
        # garbage collection might kick in at any moment
        # Therefore we must be very careful what we call
        # from here
        self.close()

    @classmethod
    def from_std(cls):
        """factory method that creates a PipeStream over the standard pipes
        (``stdin`` and ``stdout``)

        :returns: a :class:`PipeStream` instance
        """
        return cls(sys.stdin, sys.stdout)

    @classmethod
    def create_pair(cls):
        """factory method that creates two pairs of anonymous pipes, and
        creates two PipeStreams over them. Useful for ``fork()``.

        :returns: a tuple of two :class:`PipeStream` instances
        """
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        side1 = cls(os.fdopen(r1, "rb"), os.fdopen(w2, "wb"))
        side2 = cls(os.fdopen(r2, "rb"), os.fdopen(w1, "wb"))
        return side1, side2

    @property
    def closed(self):
        with self.__condition:
            if self.__ready:
                return False
            return self.incoming is ClosedFile

    def close(self):
        with self.__condition:
            incoming = self.incoming
            outgoing = self.outgoing
            self.incoming = ClosedFile
            self.outgoing = ClosedFile
            reader = self.__reader
            self.__reader = None
            self.__condition.notify_all()
        outgoing.close()
        if reader:
            reader.join(5)
        incoming.close()
        if reader and reader.is_alive():
            reader.join()
        with self.__condition:
            self.__ready = BYTES_LITERAL("")
            self.__condition.notify_all()

    def fileno(self):
        with self.__condition:
            return self.incoming.fileno()

    def notify(self):
        with self.__condition:
            self.__condition.notify()

    def poll(self, timeout, predicate=None):
        predicate_result = False

        def ready():
            nonlocal predicate_result
            predicate_result = predicate is not None and predicate()
            return (self.__ready or self.incoming is ClosedFile or predicate_result)

        with self.__condition:
            result = self.__condition.wait_for(ready, timeout.timeleft())
            if not result or predicate_result:
                return False
            if self.__ready:
                return True
            if self.incoming is ClosedFile:
                raise EOFError("stream has been closed")
            return False

    def __readthread(self, incoming):
        fd = incoming.fileno()
        if fcntl:
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        else:
            try:
                incoming.setblocking(False)
            except AttributeError:
                pass

        p = poll()
        p.register(fd, "r")

        while True:
            try:
                p.poll()
            except select_error as ex:
                if ex.args[0] == errno.EINTR:
                    continue
                buf = None
            else:
                try:
                    buf = os.read(fd, self.MAX_IO_CHUNK)
                except OSError:
                    buf = None
            with self.__condition:
                if buf:
                    self.__ready = self.__ready + buf
                else:
                    self.incoming = ClosedFile
                self.__condition.notify_all()
            if not buf:
                incoming.close()
                break

    def read(self, count):
        try:
            with self.__condition:
                self.__condition.wait_for(lambda: len(self.__ready) >= count or self.incoming is ClosedFile)
                if len(self.__ready) < count:
                    if len(self.__ready) > 0:
                        self.__ready = BYTES_LITERAL("")
                        self.__condition.notify_all()
                    raise EOFError("stream has been closed")
                data = self.__ready[:count]
                self.__ready = self.__ready[count:]
                return data
        except EOFError:
            self.close()
            raise
        except EnvironmentError as ex:
            self.close()
            raise EOFError(ex)

    def write(self, data):
        try:
            while data:
                chunk = data[:self.MAX_IO_CHUNK]
                written = os.write(self.outgoing.fileno(), chunk)
                data = data[written:]
        except EnvironmentError as ex:
            self.close()
            raise EOFError(ex)


class Win32PipeStream(Stream):
    """A stream over two simplex pipes (one used to input, another for output).
    This is an implementation for Windows pipes (which suck)"""

    __slots__ = ("incoming", "outgoing", "__fileno", "__keepalive")
    PIPE_BUFFER_SIZE = 130000
    MAX_IO_CHUNK = STREAM_CHUNK

    def __init__(self, incoming, outgoing):
        import msvcrt
        self.__keepalive = (incoming, outgoing)
        if hasattr(incoming, "fileno"):
            self.__fileno = incoming.fileno()
            try:
                set_inheritable(incoming, False)
            except OSError:
                pass
            incoming = msvcrt.get_osfhandle(incoming.fileno())
        if hasattr(outgoing, "fileno"):
            try:
                set_inheritable(outgoing, False)
            except OSError:
                pass
            outgoing = msvcrt.get_osfhandle(outgoing.fileno())
        self.incoming = incoming
        self.outgoing = outgoing

    @classmethod
    def from_std(cls):
        pipestream = cls(sys.stdin, sys.stdout)
        sys.stdin = os.open(os.devnull, os.O_RDWR)
        sys.stdout = sys.stdin
        return pipestream

    @classmethod
    def create_pair(cls):
        r1, w1 = win32pipe.CreatePipe(None, cls.PIPE_BUFFER_SIZE)
        r2, w2 = win32pipe.CreatePipe(None, cls.PIPE_BUFFER_SIZE)
        return cls(r1, w2), cls(r2, w1)

    def fileno(self):
        return self.__fileno

    @property
    def closed(self):
        return self.incoming is ClosedFile

    def close(self):
        if self.closed:
            return
        try:
            win32file.CloseHandle(self.outgoing)
        except Exception:
            pass
        self.outgoing = ClosedFile
        try:
            win32file.CloseHandle(self.incoming)
        except Exception:
            pass
        self.incoming = ClosedFile

    def read(self, count):
        try:
            data = []
            while count > 0:
                dummy, buf = win32file.ReadFile(self.incoming, int(min(self.MAX_IO_CHUNK, count)))
                count -= len(buf)
                data.append(buf)
        except TypeError as ex:
            if not self.closed:
                raise
            raise EOFError(ex)
        except win32file.error as ex:
            self.close()
            raise EOFError(ex)
        return BYTES_LITERAL("").join(data)

    def write(self, data):
        try:
            while data:
                dummy, count = win32file.WriteFile(self.outgoing, data[:self.MAX_IO_CHUNK])
                data = data[count:]
        except TypeError as ex:
            if not self.closed:
                raise
            raise EOFError(ex)
        except win32file.error as ex:
            self.close()
            raise EOFError(ex)

    def notify(self):
        pass

    def poll(self, timeout, predicate=None, interval=0.001):
        """a Windows version of select()"""
        timeout = Timeout(timeout)
        try:
            while True:
                if predicate is not None and predicate():
                    return False
                if win32pipe.PeekNamedPipe(self.incoming, 0)[1] != 0:
                    return True
                if timeout.expired():
                    return False
                timeout.sleep(interval)
        except pywintypes.error as ex:
            if ex.args[0] == 109:  # error: The pipe has been ended.
                raise EOFError(ex)
            raise
        except TypeError as ex:
            if not self.closed:
                raise
            raise EOFError(ex)


class NamedPipeStream(Win32PipeStream):
    """A stream over two named pipes (one used to input, another for output).
    Windows implementation."""

    NAMED_PIPE_PREFIX = r'\\.\pipe\rpyc_'
    PIPE_IO_TIMEOUT = 3
    CONNECT_TIMEOUT = 3

    def __init__(self, handle, is_server_side):
        super().__init__(handle, handle)
        self.is_server_side = is_server_side
        self.read_overlapped = pywintypes.OVERLAPPED()
        self.read_overlapped.hEvent = win32event.CreateEvent(None, 1, 1, None)
        self.write_overlapped = pywintypes.OVERLAPPED()
        self.write_overlapped.hEvent = win32event.CreateEvent(None, 1, 1, None)
        self.poll_buffer = win32file.AllocateReadBuffer(1)
        self.poll_read = False

    @classmethod
    def from_std(cls):
        raise NotImplementedError()

    @classmethod
    def create_pair(cls):
        raise NotImplementedError()

    @classmethod
    def create_server(cls, pipename, connect=True):
        """factory method that creates a server-side ``NamedPipeStream``, over
        a newly-created *named pipe* of the given name.

        :param pipename: the name of the pipe. It will be considered absolute if
                         it starts with ``\\\\.``; otherwise ``\\\\.\\pipe\\rpyc``
                         will be prepended.
        :param connect: whether to connect on creation or not

        :returns: a :class:`NamedPipeStream` instance
        """
        if not pipename.startswith("\\\\."):
            pipename = cls.NAMED_PIPE_PREFIX + pipename
        handle = win32pipe.CreateNamedPipe(
            pipename,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE,
            1,
            cls.PIPE_BUFFER_SIZE,
            cls.PIPE_BUFFER_SIZE,
            cls.PIPE_IO_TIMEOUT * 1000,
            None
        )
        inst = cls(handle, True)
        if connect:
            inst.connect_server()
        return inst

    def connect_server(self):
        """connects the server side of an unconnected named pipe (blocks
        until a connection arrives)"""
        if not self.is_server_side:
            raise ValueError("this must be the server side")
        win32pipe.ConnectNamedPipe(self.incoming, self.write_overlapped)
        win32event.WaitForSingleObject(self.write_overlapped.hEvent, win32event.INFINITE)

    @classmethod
    def create_client(cls, pipename):
        """factory method that creates a client-side ``NamedPipeStream``, over
        a newly-created *named pipe* of the given name.

        :param pipename: the name of the pipe. It will be considered absolute if
                         it starts with ``\\\\.``; otherwise ``\\\\.\\pipe\\rpyc``
                         will be prepended.

        :returns: a :class:`NamedPipeStream` instance
        """
        if not pipename.startswith("\\\\."):
            pipename = cls.NAMED_PIPE_PREFIX + pipename
        handle = win32file.CreateFile(
            pipename,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_OVERLAPPED,
            None
        )
        return cls(handle, False)

    def close(self):
        if self.closed:
            return
        if self.is_server_side:
            win32file.FlushFileBuffers(self.outgoing)
            win32pipe.DisconnectNamedPipe(self.outgoing)

        win32file.CloseHandle(self.write_overlapped.hEvent)
        win32file.CloseHandle(self.read_overlapped.hEvent)
        Win32PipeStream.close(self)

    def read(self, count):
        try:
            if self.poll_read:
                win32file.GetOverlappedResult(self.incoming, self.read_overlapped, 1)
                data = [self.poll_buffer[:]]
                self.poll_read = False
                count -= 1
            else:
                data = []
            while count > 0:
                hr, buf = win32file.ReadFile(self.incoming,
                                             win32file.AllocateReadBuffer(int(min(self.MAX_IO_CHUNK, count))),
                                             self.read_overlapped)
                n = win32file.GetOverlappedResult(self.incoming, self.read_overlapped, 1)
                count -= n
                data.append(buf[:n])
        except TypeError as ex:
            if not self.closed:
                raise
            raise EOFError(ex)
        except win32file.error as ex:
            self.close()
            raise EOFError(ex)
        return BYTES_LITERAL("").join(data)

    def write(self, data):
        try:
            while data:
                dummy, count = win32file.WriteFile(self.outgoing, data[:self.MAX_IO_CHUNK], self.write_overlapped)
                data = data[count:]
        except TypeError as ex:
            if not self.closed:
                raise
            raise EOFError(ex)
        except win32file.error as ex:
            self.close()
            raise EOFError(ex)

    def poll(self, timeout, predicate=None, interval=0.001):
        """Windows version of select()"""
        timeout = Timeout(timeout)
        try:
            wait_time = int(max(1, interval * 1000))

            if not self.poll_read:
                try:
                    hr, self.poll_buffer = win32file.ReadFile(self.incoming,
                                                              self.poll_buffer,
                                                              self.read_overlapped)
                except pywintypes.error as ex:
                    if ex.args[0] in (
                            109,  # error: The pipe has been ended.
                            233,  # error: No process is on the other end of the pipe.
                    ):
                        raise EOFError(ex)
                    raise
                except TypeError as ex:
                    if not self.closed:
                        raise
                    raise EOFError(ex)
                self.poll_read = True
                if hr == 0:
                    return True

            while True:
                if predicate is not None and predicate():
                    return False
                res = win32event.WaitForSingleObject(self.read_overlapped.hEvent, wait_time)
                if res == win32event.WAIT_OBJECT_0:
                    return True
                if timeout.expired():
                    return False

        except TypeError as ex:
            if not self.closed:
                raise
            raise EOFError(ex)


if sys.platform == "win32":
    PipeStream = Win32PipeStream  # noqa: F811
