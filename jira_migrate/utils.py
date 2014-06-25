from __future__ import print_function, unicode_literals

import functools
import requests
from urlobject import URLObject


class Session(object):
    def __init__(self, nick, host, username, password, debug=False):
        self.nick = nick
        self.host = URLObject(host)
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers["Content-Type"] = "application/json"
        self.debug = debug
        self.count = 0

    MSG_FMT = "{verb:4s} {nick:5s} {url}"

    @property
    def username(self):
        return self.session.auth[0]

    def get(self, url, *args, **kwargs):
        if not isinstance(url, URLObject):
            url = self.host.with_path(url)
        if self.debug:
            print(self.MSG_FMT.format(verb="GET", nick=self.nick, url=url))
        self.count += 1
        return self.session.get(url, *args, **kwargs)

    def post(self, url, *args, **kwargs):
        if not isinstance(url, URLObject):
            url = self.host.with_path(url)
        if self.debug:
            print(self.MSG_FMT.format(verb="POST", nick=self.nick, url=url))
        self.count += 1
        return self.session.post(url, *args, **kwargs)

    def put(self, url, *args, **kwargs):
        if not isinstance(url, URLObject):
            url = self.host.with_path(url)
        if self.debug:
            print(self.MSG_FMT.format(verb="PUT", nick=self.nick, url=url))
        return self.session.put(url, *args, **kwargs)

    def delete(self, url, *args, **kwargs):
        if not isinstance(url, URLObject):
            url = self.host.with_path(url)
        if self.debug:
            print(self.MSG_FMT.format(verb="DELETE", nick=self.nick, url=url))
        return self.session.delete(url, *args, **kwargs)


def paginated_api(url, obj_name, session=None, start=0, **fields):
    session = session or requests.Session()
    more_results = True
    while more_results:
        result_url = (
            url.set_query_param("startAt", str(start))
               .set_query_params(**fields)
        )
        result_resp = session.get(result_url)
        if not result_resp.ok:
            try:
                body = result_resp.json()
                err = body["errorMessages"]
            except ValueError:
                err = result_resp.text
            raise requests.exceptions.RequestException(err)
        result = result_resp.json()
        for obj in result[obj_name]:
            yield obj
        returned = len(result[obj_name])
        total = result["total"]
        if start + returned < total:
            start += returned
        else:
            more_results = False


def memoize(func):
    cache = {}

    @functools.wraps(func)
    def memoized(*args, **kwargs):
        key = (tuple(args), tuple(sorted(kwargs.items())))
        try:
            return cache[key]
        except KeyError:
            cache[key] = func(*args, **kwargs)
            return cache[key]
    return memoized
