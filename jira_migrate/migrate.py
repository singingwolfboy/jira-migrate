#!/usr/bin/env python
from __future__ import print_function, unicode_literals

import argparse
from ConfigParser import SafeConfigParser
import itertools
import json
from pprint import pprint
import re
import sys

import requests

from .utils import memoize, paginated_api, Session


def parse_arguments(argv):
    parser = argparse.ArgumentParser(
        description="Migrate JIRA tickets",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--debug", default="")
    parser.add_argument("--jql",
        help="The JIRA JQL query to find issues to migrate",
        default="project = LMS AND created >= -6w",
    )
    parser.add_argument("--limit", type=int,
        help="Don't migrate more than this many issues",
    )
    parser.add_argument("--no-idempotent", dest="idempotent",
        action="store_const", const=False, default=True,
        help="Create new issues for already-migrated issues",
    )

    args = parser.parse_args(argv[1:])

    args.debug = args.debug.split(",")

    return args

CMDLINE_ARGS = parse_arguments(sys.argv)

SPRINT_RE = re.compile(
    r"""
    com\.atlassian\.greenhopper\.service\.sprint\.Sprint  # Java classpath
    @[0-9a-f]+  # memory address
    \[  # begin attributes
    rapidViewId=(?P<rapidViewId>[^,]+),
    state=(?P<state>[^,]+),
    name=(?P<name>[^,]+),
    startDate=(?P<startDate>[^,]+),
    endDate=(?P<endDate>[^,]+),
    completeDate=(?P<completeDate>[^,]+),
    id=(?P<id>[^,]+)
    \]  # end attributes
    """,
    re.VERBOSE
)

config = SafeConfigParser()
files_read = config.read("config.ini")
if not files_read:
    print("Couldn't read config.ini")
    sys.exit(1)

old_session = Session(
    nick="old  ",
    host=config.get("origin", "host"),
    username=config.get("origin", "username"),
    password=config.get("origin", "password"),
    debug="requests" in CMDLINE_ARGS.debug,
)
old_host = old_session.host

new_session = Session(
    nick="  new",
    host=config.get("destination", "host"),
    username=config.get("destination", "username"),
    password=config.get("destination", "password"),
    debug="requests" in CMDLINE_ARGS.debug,
)
new_host = new_session.host

# simple name-to-id mappings for our new instance
name_to_id = {}
for field in ("project", "issuetype", "priority", "resolution", "status"):
    url = new_host.with_path("/rest/api/2/" + field)
    resp = new_session.get(url)
    info = {x["name"]: x["id"] for x in resp.json()}
    name_to_id[field] = info


# grab field information
old_field_url = old_host.with_path("/rest/api/2/field")
old_field_resp = old_session.get(old_field_url)
old_fields = {f["id"]: f["name"] for f in old_field_resp.json() if f["custom"]}
new_field_url = new_host.with_path("/rest/api/2/field")
new_field_resp = new_session.get(new_field_url)
new_fields = {f["id"]: f["name"] for f in new_field_resp.json() if f["custom"]}

if 0:
    print("OLD FIELDS")
    pprint(old_fields)
    print("NEW FIELDS")
    pprint(new_fields)

# old-to-new mapping
new_fields_name_to_id = {name: id for id, name in new_fields.items()}
old_fields_name_to_id = {name: id for id, name in old_fields.items()}
field_map = {old_id: new_fields_name_to_id[name] for old_id, name in old_fields.items()
             if name in new_fields_name_to_id}

for name in ["Migrated Sprint", "Migrated Status"]:
    if name not in new_fields_name_to_id:
        print("You need to create a {} labels custom field in the new JIRA".format(name))
        sys.exit(1)


fields_that_cannot_be_set = set((
    "aggregateprogress", "created", "creator", "progress", "status", "updated",
    "votes", "watches", "workratio", "lastViewed", "resolution", "resolutiondate",
    # find a way to do these:
    "environment",
    # structural things we do another way:
    "subtasks", "comment",
    # custom fields that cannot be set
    new_fields_name_to_id["Rank"],
    new_fields_name_to_id["Rank (Obsolete)"],
    new_fields_name_to_id["Testing Status"],
    new_fields_name_to_id["[CHART] Time in Status"],
    new_fields_name_to_id["[CHART] Date of First Response"],
))


@memoize
def get_or_create_user(host, username, name, email, session=None):
    session = session or requests.Session()
    user_url = host.with_path("/rest/api/2/user").set_query_param("username", username)
    user_resp = session.get(user_url)
    if user_resp.ok:
        return user_resp.json()
    # user doesn't exist!
    data = {
        "name": username,
        "emailAddress": email,
        "displayName": name,
    }
    create_resp = session.post(user_url, data=json.dumps(data))
    if create_resp.ok:
        return create_resp.json()
    else:
        raise requests.exceptions.RequestException(create_resp.text)


def transform_old_issue_to_new(old_issue):
    new_issue_fields = {}
    for field, value in old_issue["fields"].items():
        if field.startswith("custom"):
            if field in field_map:
                field = field_map[field]
            else:
                continue
            if field == new_fields_name_to_id["Sprint"] and value:
                field = new_fields_name_to_id["Migrated Sprint"]
                value = []
                for sprint in [parse_sprint_string(s) for s in value]:
                    if sprint:
                        value.append(sprint["name"])
        elif field == "status":
            # can't set status directly, so use a custom field
            field = new_fields_name_to_id["Migrated Status"]
            value = [value["name"]]
        elif field in name_to_id and value:
            try:
                value = {"id": name_to_id[field][value["name"]]}
            except KeyError:
                raise KeyError("{name} is not a valid {field}".format(
                    name=value["name"], field=field
                ))
        if value and field not in fields_that_cannot_be_set:
            new_issue_fields[field] = value

    new_issue = {"fields": new_issue_fields}
    # it would be nice if we could specify the key for the new issue,
    # but this doesn't appear to actually do anything. :(
    new_issue["key"] = old_issue["key"]

    return new_issue


def parse_sprint_string(sprint_str):
    match = SPRINT_RE.match(sprint_str)
    if not match:
        return None
    result = match.groupdict()
    for prop, value in result.items():
        if value == "<null>":
            result[prop] = None
    for prop in ("id", "rapidViewId"):
        if result[prop]:
            result[prop] = int(result[prop])
    return result


def migrate_issue(old_issue, idempotent=True):
    """Migrate an issue, but only once.

    If the issue has already been migrated, this does nothing.

    Returns a tuple of (new_key, migrated_boolean)
    """
    old_key = old_issue["key"]

    # if this is idempotent, first check if this issue has already been migrated.
    if idempotent:
        old_link_url = old_host.with_path("/rest/api/2/issue/{key}/remotelink".format(key=old_key))
        old_link_resp = old_session.get(old_link_url)
        if old_link_resp.ok:
            for old_link in old_link_resp.json():
                url = old_link["object"].get("url", "")
                title = old_link["object"].get("title", "")
                if str(new_host) in url and "Migrated Issue" in title:
                    # already been migrated!
                    new_key = url.rsplit("/", 1)[-1]
                    return new_key, False
        else:
            print("Warning: could not check for idempotency for {key}".format(
                key=old_key
            ))

    # If the issue has a parent, then we need to migrate the parent first.
    if old_issue['fields'].get('parent', None):
        parent_key = old_issue['fields']['parent']['key']
        print("Migrating parent {}".format(parent_key))
        new_parent_key, _ = migrate_issue_by_key(parent_key)
        old_issue['fields']['parent'] = {'key': new_parent_key}

    # If the issue is in an epic, we need to migrate the epic first.
    epic_field_id = old_fields_name_to_id["Epic Link"]
    if old_issue['fields'].get(epic_field_id, None):
        epic_key = old_issue['fields'][epic_field_id]
        print("Migrating epic {}".format(epic_key))
        new_epic_key, _ = migrate_issue_by_key(epic_key)
        old_issue['fields'][epic_field_id] = new_epic_key

    if "subtasks" in old_issue:
        subtasks = [st["key"] for st in old_issue["subtasks"]]
    else:
        subtasks = []

    user_fields = ["creator", "assignee", "reporter"]
    for field in user_fields:
        user_info = old_issue["fields"][field]
        if user_info:
            get_or_create_user(
                host=new_host,
                username=user_info["name"],
                name=user_info["displayName"],
                email=user_info["emailAddress"],
                session=new_session,
            )

    new_issue = transform_old_issue_to_new(old_issue)
    new_issue_url = new_host.with_path("/rest/api/2/issue")
    new_issue_resp = new_session.post(new_issue_url, data=json.dumps(new_issue))
    if not new_issue_resp.ok:
        errors = new_issue_resp.json()["errors"]
        for field, message in errors.items():
            if field in new_fields:
                errors[field] += " ({})".format(new_fields[field])
        print("=" * 20, " tried to make:")
        pprint(new_issue)
        print("=" * 20, " got this back:")
        pprint(new_issue_resp.json())
        print("=" * 20)
        pprint(errors)
        return None, False

    new_key = new_issue_resp.json()["key"]

    # migrate comments
    old_comments_url = old_host.with_path("/rest/api/2/issue/{key}/comment".format(key=old_key))
    new_comments_url = new_host.with_path("/rest/api/2/issue/{key}/comment".format(key=new_key))
    for old_comment in paginated_api(old_comments_url, "comments", session=old_session):
        for field in ("author", "updateAuthor"):
            user_info = old_comment.get(field, {})
            if user_info:
                get_or_create_user(
                    host=new_host,
                    username=user_info["name"],
                    name=user_info.get("displayName", ""),
                    email=user_info.get("emailAddress", ""),
                    session=new_session,
                )
        # can't set the comment author or creation date, so prefix those in the comment body
        prefix = "[~{author}] commented on {date}:\n\n".format(
            author=old_comment["author"]["name"], date=old_comment["created"]
        )
        old_comment["body"] = prefix + old_comment["body"]
        new_session.post(new_comments_url, data=json.dumps(old_comment))

    # link new to old
    new_link_url = new_host.with_path("/rest/api/2/issue/{key}/remotelink".format(key=new_key))
    new_link_data = {
        "object": {
            "url": old_host.with_path("/browse/{key}".format(key=old_key)),
            "title": "Original Issue ({key})".format(key=old_key),
        }
    }
    new_link_resp = new_session.post(new_link_url, data=json.dumps(new_link_data))
    if not new_link_resp.ok:
        print("Linking new to old failed")
        errors = new_link_resp.json()["errors"]
        pprint(errors)

    # link old to new
    old_link_url = old_host.with_path("/rest/api/2/issue/{key}/remotelink".format(key=old_key))
    old_link_data = {
        "object": {
            "url": new_host.with_path("/browse/{key}".format(key=new_key)),
            "title": "Migrated Issue ({key})".format(key=new_key),
        }
    }
    old_link_resp = old_session.post(old_link_url, data=json.dumps(old_link_data))
    if not new_link_resp.ok:
        print("Linking old to new failed")
        errors = old_link_resp.json()["errors"]
        pprint(errors)

    # migrate the subtasks
    for key in subtasks:
        print("Migrating subtask {}".format(key))
        migrate_issue_by_key(key)

    return new_key, True


def migrate_issue_by_key(key, idempotent=True):
    issue_url = old_host.with_path("/rest/api/2/issue/{key}".format(key=key))
    issue_resp = old_session.get(issue_url)
    if issue_resp.ok:
        return migrate_issue(issue_resp.json(), idempotent=idempotent)
    else:
        raise Exception("Couldn't get issue by key: {}".format(issue_resp.text))


def main():
    search_url = (
        old_host.with_path("/rest/api/2/search")
                .add_query_param("jql", CMDLINE_ARGS.jql)
    )
    issues = paginated_api(search_url, obj_name="issues", session=old_session)
    for issue in itertools.islice(issues, CMDLINE_ARGS.limit):
        old_key = issue["key"]
        new_key, migrated = migrate_issue(issue, idempotent=CMDLINE_ARGS.idempotent)
        if migrated:
            print("Migrated {old} to {new}".format(old=old_key, new=new_key))
        else:
            print("{old} was previously migrated to {new}".format(old=old_key, new=new_key))