# Select.poll is not always available

class Poll:
    def __init__(self):
        self.fd_map = {}

    def register(self, fd, mask):
        self.fd_map[fd] = mask

    def unregister(self, fd):
        del self.fd_map[fd]

    def modify(self, fd, mask):
        if fd not in self.fd_map:
            raise IOError(2, 'No such file or directory')
        self.fd_map[fd] = mask

    def poll(self, timeout=None):
        rlist = [x for x in self.fd_map if self.fd_map[x] & select.POLLIN]
        wlist = [x for x in self.fd_map if self.fd_map[x] & select.POLLOUT]
        elist = [x for x in self.fd_map if self.fd_map[x] & select.POLLERR]

        (rev, wev, eev) = select.select(rlist, wlist, elist, timeout)
        return [(f, select.POLLIN) for f in rev] + \
               [(f, select.POLLOUT) for f in wev] + \
               [(f, select.POLLERR) for f in eev]

try:
    from select import poll
except ImportError:
    import select
    select.POLLERR = 8
    select.POLLHUP = select.POLLERR
    select.POLLIN = 1
    select.POLLOUT = 4
    select.poll = Poll
