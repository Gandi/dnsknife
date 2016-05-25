from .exceptions import NoAnswer, BadRcode, Timeout
import multiprocessing

"""
with dnsknife.async.Wrapper(c) as async:
    for ns in big_list_of_ns:
        async.query_at(ns, 'www', 'A')
    one = async.get_one()

    for ns in big_list:
        for type in many_types:
            async.query_at(ns, 'www', type)
    all = async.get_all()
"""


def checker_call(checker, name, *args):
    return getattr(checker, name)(*args)


class Wrapper:

    def __init__(self, checker, nr=8):
        self.checker = checker
        self.pool = multiprocessing.Pool(nr)
        self.pending = []

    def wrap(self, checker, name):
        def wrapped(*args):
            res = self.pool.apply_async(checker_call,
                                        (self.checker, name,)+args,)
            self.pending.append(res)
        return wrapped

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.pool.terminate()

    def __getattr__(self, name):
        if (not name.startswith('_') and
            callable(getattr(self.checker, name, None))):
            return self.wrap(self.checker, name)
        return getattr(self.checker, name)

    def get_one(self):
        # We cannot use a callback/semaphore/condition here
        # as errors are not propagated. That sucks
        while True:
            for res in self.pending:
                if res.ready():
                    self.pending.remove(res)
                    try:
                        return res.get()
                    except Exception as e:
                        return e

    def get_all(self):
        while self.pending:
            try:
                yield self.get_one()
            except (NoAnswer, BadRcode, Timeout) as e:
                yield e
