from __future__ import print_function, unicode_literals

import argparse
import ConfigParser
import sys

import requests

from .utils import Session


def parse_arguments(argv):
    parser = argparse.ArgumentParser(
        description="Delete JIRA users",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--debug", default="")
    parser.add_argument("--no-save", dest="save",
        action="store_const", const=False, default=True,
        help="Don't save the users specified in the config file",
    )

    args = parser.parse_args(argv[1:])

    args.debug = args.debug.split(",")

    return args

CMDLINE_ARGS = parse_arguments(sys.argv)

config = ConfigParser.SafeConfigParser()
files_read = config.read("config.ini")
if not files_read:
    print("Couldn't read config.ini")
    sys.exit(1)

session = Session(
    nick="  new",
    host=config.get("destination", "host"),
    username=config.get("destination", "username"),
    password=config.get("destination", "password"),
    debug="requests" in CMDLINE_ARGS.debug,
)

try:
    users_to_save = set(config.get("users", "save").split(","))
except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
    users_to_save = set()


def iter_users_in_group(host, group="jira-users", session=None, start=0, **fields):
    session = session or requests.Session()
    more_results = True
    while more_results:
        result_url = (
            host.with_path("/rest/api/2/group")
                .set_query_param("groupname", group)
                .set_query_param("expand", "users[{start}:{end}]".format(
                    start=start, end=start + 50))
                .set_query_params(**fields)
        )
        result_resp = session.get(result_url)
        result = result_resp.json()
        for obj in result["users"]["items"]:
            yield obj
        returned = len(result["users"]["items"])
        total = result["users"]["size"]
        if start + returned < total:
            start += returned
        else:
            more_results = False


def delete_jira_users():
    user_gen = iter_users_in_group(host=session.host, session=session)
    for user in user_gen:
        if user["name"] not in users_to_save:
            delete_url = (
                session.host.with_path("/rest/api/2/user")
                .set_query_param("username", user["name"])
            )
            delete_resp = session.delete(delete_url)
            if not delete_resp.ok:
                raise ValueError(delete_resp.text)
