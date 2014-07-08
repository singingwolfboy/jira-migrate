#!/usr/bin/env python
from __future__ import print_function, unicode_literals

import argparse
from ConfigParser import SafeConfigParser, NoOptionError
import itertools
import operator
from pprint import pprint
import re
import time

from urlobject import URLObject
import requests
from requests.compat import json

from .jira import Jira, MissingUserInfo, MAPPED_RESOURCES
from .utils import memoize


class ConfigurationError(Exception):
    pass


class JiraIssueError(Exception):
    pass


class JiraIssueSkip(Exception):
    pass


class JiraMigrator(object):
    def __init__(self, config, debug, all_private=False):
        self.all_private = all_private

        self.success = {}       # map from old key to new key
        self.failure = set()    # set of failed old keys
        self.skip = set()       # set of skipped old keys

        # a list of iterables that produce issue to migrate
        self.issue_iterables = []

        try:
            ignored_issues_str = config.get("origin", "ignore")
            self.ignored_issues = set(ignored_issues_str.split(","))
        except NoOptionError:
            self.ignored_issues = set()
        try:
            private_issues_str = config.get("origin", "private")
            self.private_issues = set(private_issues_str.split(","))
        except NoOptionError:
            self.private_issues = set()
        try:
            self.ignore_label = config.get("origin", "ignore-label")
        except NoOptionError:
            self.ignore_label = None
        try:
            self.private_label = config.get("origin", "private-label")
        except NoOptionError:
            self.private_label = None

        self.old_jira = Jira("old  ", config, "origin", debug)
        self.new_jira = Jira("  new", config, "destination", debug)

        self.fetch_field_info()

    def succeeded(self, old_key, new_key):
        self.success[old_key] = new_key

    def failed(self, key):
        self.failure.add(key)

    def skipped(self, key):
        self.skip.add(key)

    def also_run_issue(self, key):
        self.issue_iterables.append([key])

    def also_run_issues(self, keys):
        self.issue_iterables.append(keys)

    def fetch_field_info(self):
        # grab field information
        self.old_custom_fields = self.old_jira.custom_field_map
        self.new_custom_fields = self.new_jira.custom_field_map

        # invert it: name to ID
        self.old_custom_fields_inv = {name: id for id, name in self.old_custom_fields.items()}
        self.new_custom_fields_inv = {name: id for id, name in self.new_custom_fields.items()}

        # map of custom field ID on the old JIRA to custom field ID on the new JIRA
        # (only contains fields present on old instance)
        self.custom_fields_old_id_to_new_id = {
            old_id: self.new_custom_fields_inv[name]
            for old_id, name in self.old_custom_fields.items()
            if name in self.new_custom_fields_inv
        }

        for name in ("Migrated New Key",):
            if name not in self.old_custom_fields_inv:
                raise JiraIssueError("You need to create a {} custom field in the old JIRA".format(name))

        for name in ("Migrated Sprint", "Migrated Status", "Migrated Original Key", "Migrated Creation Date"):
            if name not in self.new_custom_fields_inv:
                raise JiraIssueError("You need to create a {} custom field in the new JIRA".format(name))

        # For these fields, we'll attempt to set the value on the migrated ticket,
        # but if it fails, then we'll retry without setting the field.
        self.attempted_fields = set((
            self.new_custom_fields_inv["Business Value"],
            self.new_custom_fields_inv["Flagged"],
            # we can't set story points on subtasks, because JIRA is annoying
            self.new_custom_fields_inv["Story Points"],
        ))

        # Don't even try to set these fields -- it just won't work.
        self.ignored_fields = set((
            "aggregateprogress", "created", "creator", "progress", "status", "updated",
            "votes", "watches", "workratio", "lastViewed", "resolutiondate",
            "worklog", "timespent", "aggregatetimespent", "fixVersions",
            # find a way to do these:
            "environment", "issuelinks",
            # structural things we do another way:
            "subtasks", "comment", "attachment", "resolution",
            # custom fields that cannot be set
            self.new_custom_fields_inv["Rank (Obsolete)"],
            self.new_custom_fields_inv["Testing Status"],
            self.new_custom_fields_inv["[CHART] Time in Status"],
            self.new_custom_fields_inv["[CHART] Date of First Response"],
            self.new_custom_fields_inv["Epic Status"],
        ))

    def should_issue_be_private(self, issue_info):
        if self.all_private:
            return True
        if issue_info["key"] in self.private_issues:
            return True
        if self.private_label and self.private_label in issue_info["fields"]["labels"]:
            return True
        return False

    def transform_old_issue_to_new(self, old_issue, warnings):
        new_issue_fields = {}
        for field, value in old_issue["fields"].items():
            if field.startswith("custom"):
                if field in self.custom_fields_old_id_to_new_id:
                    field = self.custom_fields_old_id_to_new_id[field]
                else:
                    continue
                if field == self.new_custom_fields_inv["Sprint"] and value:
                    field = self.new_custom_fields_inv["Migrated Sprint"]
                    new_value = []
                    for sprint in [self.parse_sprint_string(s) for s in value]:
                        if sprint:
                            new_value.append(sprint["name"].replace(" ", "_"))
                    value = new_value
            elif field == "status":
                # can't set status directly, so use a custom field
                field = self.new_custom_fields_inv["Migrated Status"]
                value = [value["name"].replace(" ", "_")]
            elif field in MAPPED_RESOURCES and value:
                try:
                    field_map = self.new_jira.resource_map(field)
                    field_map_inv = {name: id for id, name in field_map.items()}
                    value = {"id": field_map_inv[value["name"]]}
                except KeyError:
                    warnings.append("{name!r} is not a valid {field!r}".format(
                        name=value["name"], field=field
                    ))
            if value and field not in self.ignored_fields:
                new_issue_fields[field] = value

        if self.should_issue_be_private(old_issue):
            new_issue_fields["security"] = {"name": "Private"}

        # Store the original key.
        new_issue_fields[self.new_custom_fields_inv["Migrated Original Key"]] = old_issue["key"]
        # Store the original creation date
        new_issue_fields[self.new_custom_fields_inv["Migrated Creation Date"]] = old_issue["fields"]["created"]

        new_issue = {"fields": new_issue_fields}
        # it would be nice if we could specify the key for the new issue,
        # but this doesn't appear to actually do anything. :(
        new_issue["key"] = old_issue["key"]

        return new_issue

    def scrub_noise(self, data):
        """Remove things that don't need to be in POSTed issues, and just clutter output."""
        for key, value in data.iteritems():
            if isinstance(value, dict):
                self.scrub_noise(value)
            if isinstance(value, list) and value and isinstance(value[0], dict):
                for subvalue in value:
                    self.scrub_noise(subvalue)
        for key in ["avatarUrls", "self"]:
            if key in data:
                del data[key]

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

    def parse_sprint_string(self, sprint_str):
        match = self.SPRINT_RE.match(sprint_str)
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

    @memoize
    def has_issue_migrated(self, old_key):
        old_link_resp = self.old_jira.get("/rest/api/2/issue/{key}/remotelink".format(key=old_key))
        if old_link_resp.ok:
            migrated_issues = []
            try:
                old_links = old_link_resp.json()
            except json.JSONDecodeError:
                msg = "Invalid JSON: {}".format(old_link_resp.text)
                raise requests.exceptions.RequestException(msg)

            for old_link in old_links:
                url = old_link["object"].get("url", "")
                title = old_link["object"].get("title", "")
                if str(self.new_jira.host) in url and "Migrated Issue" in title:
                    # Already been migrated once!
                    new_key = url.rsplit("/", 1)[-1]
                    # Does the new issue still exist?
                    if self.new_jira.get_issue(new_key):
                        migrated_issues.append(new_key)
                    else:
                        # if not, remove the link
                        self.old_jira.delete(
                            "/rest/api/2/issue/{key}/remotelink/{link_id}".format(
                                key=old_key, link_id=old_link["id"]
                            )
                        )
            if migrated_issues:
                # return the first one
                return migrated_issues[0]
        else:
            print("Warning: could not check for idempotency for {key}".format(
                key=old_key
            ))
        return None

    def migrate_issue(self, old_issue, idempotent=True):
        """Migrate an issue, but only once.

        If the issue has already been migrated, this does nothing.

        Returns a tuple of (new_key, migrated_boolean)
        """
        old_key = old_issue["key"]
        warnings = []

        # should this be ignored?
        if old_key in self.ignored_issues:
            raise JiraIssueSkip("Ignored by configuration")

        # if this is idempotent, first check if this issue has already been migrated.
        if idempotent:
            new_key = self.has_issue_migrated(old_key)
            if new_key:
                return new_key, False

        # If the issue has a parent, then we need to migrate the parent first.
        if old_issue['fields'].get('parent', None):
            parent_key = old_issue['fields']['parent']['key']
            print("Migrating parent {}".format(parent_key))
            new_parent_key = self.migrate_issue_by_key(parent_key)
            if not new_parent_key:
                raise JiraIssueSkip("Parent was not migrated, so child cannot be migrated ({})".format(old_key))
            old_issue['fields']['parent'] = {'key': new_parent_key}

        # If the issue is in an epic, we need to migrate the epic first.
        epic_field_id = self.old_custom_fields_inv["Epic Link"]
        if old_issue['fields'].get(epic_field_id, None):
            epic_key = old_issue['fields'][epic_field_id]
            print("Migrating epic {}".format(epic_key))
            new_epic_key = self.migrate_issue_by_key(epic_key)
            if not new_epic_key:
                raise JiraIssueSkip("Epic was not migrated, so issue cannot be migrated ({})".format(old_key))
            old_issue['fields'][epic_field_id] = new_epic_key

        if "subtasks" in old_issue["fields"]:
            self.also_run_issues(st["key"] for st in old_issue["fields"]["subtasks"])

        user_fields = ["creator", "assignee", "reporter"]
        for field in user_fields:
            user_info = old_issue["fields"][field]
            if user_info:
                self.new_jira.get_or_create_user(user_info)

        new_issue = self.transform_old_issue_to_new(old_issue, warnings)
        self.scrub_noise(new_issue)

        new_issue_resp = self.new_jira.post("/rest/api/2/issue", as_json=new_issue)
        try:
            new_issue_body = new_issue_resp.json()
        except json.JSONDecodeError:
            msg = "Invalid JSON: {}".format(new_issue_resp.text)
            raise requests.exceptions.RequestException(msg)

        if not new_issue_resp.ok:
            # remove anything from the attempted_fields that causes trouble
            error_fields = new_issue_body["errors"].keys()
            unset_error_field = False
            for error_field in error_fields:
                if error_field in self.attempted_fields:
                    del new_issue["fields"][error_field]
                    unset_error_field = True
            if unset_error_field:
                # try again
                new_issue_resp = self.new_jira.post("/rest/api/2/issue", as_json=new_issue)
                try:
                    new_issue_body = new_issue_resp.json()
                except json.JSONDecodeError:
                    msg = "Invalid JSON: {}".format(new_issue_resp.text)
                    raise requests.exceptions.RequestException(msg)

        if not new_issue_resp.ok:
            errors = new_issue_body["errors"]
            for field, _ in errors.items():
                if field in self.new_custom_fields_inv:
                    errors[field] += " ({})".format(self.new_custom_fields_inv[field])
            print("=" * 20, " tried to make:")
            pprint(new_issue)
            print("=" * 20, " got this back:")
            pprint(new_issue_body)
            print("=" * 20)
            pprint(errors)
            raise JiraIssueError(errors)

        new_key = new_issue_body["key"]

        # transition to the correct status
        status = old_issue["fields"]["status"]["name"]
        if old_issue["fields"]["resolution"]:
            resolution = old_issue["fields"]["resolution"]["name"]
        else:
            resolution = None
        self.new_jira.transition(new_key, status, resolution=resolution)

        # A number of things get added as comments.  We collect them up, sort
        # them by date, and add them all at the end.
        comments = []
        new_comments_url = "/rest/api/2/issue/{key}/comment".format(key=new_key)

        # Add a comment with the creation date
        comments.append({
            "body": None,
            "author": old_issue["fields"]["creator"],
            "migrated_verb": "created original issue [{key}|{url}]".format(
                key=old_key,
                url=self.old_jira.url("/browse/{key}".format(key=old_key)),
            ),
            "created": old_issue["fields"]["created"],
        })

        # Migrate comments.
        for comment in old_issue["fields"]["comment"]["comments"]:
            for field in ("author", "updateAuthor"):
                user_info = comment.get(field, {})
                if user_info:
                    self.new_jira.get_or_create_user(user_info)

            comment["migrated_verb"] = "commented"
            comments.append(comment)

        # Migrate attachments.  Re-attaching them is complicated, let's make
        # comments with links to the old-jira attachment.
        for old_attach in old_issue["fields"]["attachment"]:
            self.new_jira.get_or_create_user(old_attach['author'])
            comment = {
                "author": old_attach["author"],
                "body": None,
                "created": old_attach["created"],
                "migrated_verb": "attached [{filename}|{url}]".format(
                    filename=old_attach["filename"],
                    url=old_attach["content"],
                ),
            }
            comments.append(comment)

        # Add all the comments to the new issue, in chronological order.
        comments.sort(key=operator.itemgetter("created"))
        for comment in comments:
            if comment["author"]:
                author = "[~{username}]".format(username=comment["author"]["name"])
            else:
                author = "Anonymous"
            # can't set the comment author or creation date, so prefix those in the comment body
            body = "\u25ba{author} {verb} on {date}".format(
                author=author,
                date=comment["created"],
                verb=comment["migrated_verb"],
            )
            if comment["body"]:
                body += ":\n\n" + comment["body"]
            comment["body"] = body
            self.new_jira.post(new_comments_url, as_json=comment)

        # Migrate watchers. Must happen after comments, since adding a comment
        # implicitly makes you watch the issue.
        old_watchers_resp = self.old_jira.get("/rest/api/2/issue/{key}/watchers".format(key=old_key))
        new_watchers_url = self.new_jira.url("/rest/api/2/issue/{key}/watchers".format(key=new_key))
        try:
            old_watchers_body = old_watchers_resp.json()
        except json.JSONDecodeError:
            msg = "Invalid JSON: {}".format(old_watchers_resp.text)
            raise requests.exceptions.RequestException(msg)
        watcher_usernames = set(w["name"] for w in old_watchers_body["watchers"])
        # When we create an issue, we are a watcher on it by default.
        # Remove ourselves from the watcher list if necessary.
        new_username = self.new_jira.session.username
        if new_username not in watcher_usernames:
            self.new_jira.delete(
                new_watchers_url.set_query_param("username", new_username)
            )
        # add all the watchers in the list
        for watcher in old_watchers_body["watchers"]:
            try:
                self.new_jira.get_or_create_user(watcher)
            except MissingUserInfo:
                user_url = URLObject(watcher["self"])
                user_info_resp = self.old_jira.get(user_url)
                self.new_jira.create_user(user_info_resp.json())
            self.new_jira.post(new_watchers_url, as_json=watcher["name"])

        # link new to old
        self.new_jira.make_link(
            new_key,
            url=self.old_jira.url("/browse/{key}".format(key=old_key)),
            title="Original Issue ({key})".format(key=old_key),
        )

        # link old to new
        if idempotent:
            self.old_jira.make_link(
                old_key,
                url=self.new_jira.url("/browse/{key}".format(key=new_key)),
                title="Migrated Issue ({key})".format(key=new_key),
            )
            new_key_field = self.old_custom_fields_inv["Migrated New Key"]
            data = {
                "fields": {
                    new_key_field: new_key,
                }
            }
            new_key_resp = self.old_jira.put(
                "/rest/api/2/issue/{key}".format(key=old_key),
                as_json=data,
            )
            if not new_key_resp.ok:
                raise JiraIssueError(new_key_resp.text)

        self.has_issue_migrated.uncache(old_key)

        if warnings:
            print("***    warnings:")
            for warning in warnings:
                print("***      {}".format(warning))

        return new_key, True

    def sync_issue(self, old_key=None, new_key=None, forwards=False):
        """
        Match the state of the new issue to the state of the old issue
        """
        if not old_key and not new_key:
            raise ValueError("Must specify either new_key or old_key")

        if new_key:
            new_issue_resp = self.new_jira.get("/rest/api/2/issue/{key}".format(key=new_key))
            if new_issue_resp.status_code == 404:
                raise JiraIssueError("Issue {key} on new JIRA no longer exists!".format(key=new_key))
            if not new_issue_resp.ok:
                raise JiraIssueError("Error fetching {key} from new JIRA: {}".format(new_issue_resp.text))
            try:
                new_issue = new_issue_resp.json()
            except json.JSONDecodeError:
                msg = "Invalid JSON: {}".format(new_issue_resp.text)
                raise requests.exceptions.RequestException(msg)
            new_fields = new_issue["fields"]

            if not old_key:
                old_key_field = self.new_custom_fields_inv["Migrated Original Key"]
                old_key = new_fields[old_key_field]
                if not old_key:
                    msg = (
                        "Issue {key} on new JIRA doesn't have a corresponding "
                        "key on the old JIRA".format(key=new_key)
                    )
                    raise JiraIssueError(msg)

        old_issue_resp = self.old_jira.get("/rest/api/2/issue/{key}".format(key=old_key))
        if old_issue_resp.status_code == 404:
            raise JiraIssueError("Issue {key} on old JIRA no longer exists!".format(key=old_key))
        if not old_issue_resp.ok:
            raise JiraIssueError("Error fetching {key} from old JIRA: {}".format(old_issue_resp.text))
        try:
            old_issue = old_issue_resp.json()
        except json.JSONDecodeError:
            msg = "Invalid JSON: {}".format(old_issue_resp.text)
            raise requests.exceptions.RequestException(msg)
        old_fields = old_issue["fields"]

        if not new_key:
            new_key_field = self.old_custom_fields_inv["Migrated New Key"]
            new_key = old_fields[new_key_field]
            if not new_key:
                msg = (
                    "Issue {key} on old JIRA doesn't have a corresponding "
                    "key on the new JIRA".format(key=old_key)
                )
                raise JiraIssueError(msg)

            new_issue_resp = self.new_jira.get("/rest/api/2/issue/{key}".format(key=new_key))
            if new_issue_resp.status_code == 404:
                raise JiraIssueError("Issue {key} on new JIRA no longer exists!".format(key=new_key))
            if not new_issue_resp.ok:
                raise JiraIssueError("Error fetching {key} from new JIRA: {}".format(new_issue_resp.text))
            try:
                new_issue = new_issue_resp.json()
            except json.JSONDecodeError:
                msg = "Invalid JSON: {}".format(new_issue_resp.text)
                raise requests.exceptions.RequestException(msg)
            new_fields = new_issue["fields"]

        # determine "primary" and "replica": replica always changes to match primary
        if forwards:
            primary_key = old_key
            primary_fields = old_fields
            primary_jira = self.old_jira
            primary_custom_fields = self.old_custom_fields_inv
            replica_key = new_key
            replica_fields = new_fields
            replica_jira = self.new_jira
            replica_custom_fields = self.new_custom_fields_inv
        else:
            primary_key = new_key
            primary_fields = new_fields
            primary_jira = self.new_jira
            primary_custom_fields = self.new_custom_fields_inv
            replica_key = old_key
            replica_fields = old_fields
            replica_jira = self.old_jira
            replica_custom_fields = self.old_custom_fields_inv

        made_changes = False
        updated_resolution = False

        # check status and resolution
        if primary_fields["status"]["name"] != replica_fields["status"]["name"]:
            if primary_fields["resolution"]:
                resolution = primary_fields["resolution"]["name"]
            else:
                resolution = None
            replica_jira.transition(replica_key, primary_fields["status"]["name"], resolution=resolution)
            made_changes = True
            updated_resolution = True

        update_fields = {}

        # check labels
        if primary_fields["labels"] != replica_fields["labels"]:
            update_fields["labels"] = primary_fields["labels"]

        # check priority
        if primary_fields["priority"]["name"] != replica_fields["priority"]["name"]:
            p_priority_name = primary_fields["priority"]["name"]
            r_priority_map = replica_jira.resource_map("priority")
            r_priority_map_inv = {name: id for id, name in r_priority_map.items()}
            update_fields["priority"] = {"id": r_priority_map_inv[p_priority_name]}

        # check story points
        p_story_points = primary_custom_fields["Story Points"]
        r_story_points = replica_custom_fields["Story Points"]
        sp_needs_update = (
            p_story_points in primary_fields and
            r_story_points in replica_fields and
            primary_fields[p_story_points] != replica_fields[r_story_points]
        )
        if sp_needs_update:
            update_fields[r_story_points] = primary_fields[p_story_points]

        # check assignee: the "assignee" field can be a dict, or None
        if primary_fields["assignee"] is None:
            if replica_fields["assignee"] is not None:
                update_fields["assignee"] = None
        else:
            p_assignee_name = primary_fields["assignee"]["name"]
            if replica_fields["assignee"] is None or replica_fields["assignee"]["name"] != p_assignee_name:
                replica_jira.get_or_create_user(primary_fields["assignee"])
                update_fields["assignee"] = {"name": p_assignee_name}

        # if we're syncing forwards, make sure we've set the original creation date
        migrated_creation_date_field = self.new_custom_fields_inv["Migrated Creation Date"]
        if forwards and not new_fields[migrated_creation_date_field]:
            update_fields[migrated_creation_date_field] = old_fields["created"]

        # do the update!
        if update_fields:
            data = {"fields": update_fields}
            update_resp = replica_jira.put(
                "/rest/api/2/issue/{key}".format(key=replica_key), as_json=data)
            made_changes = True
            if not update_resp.ok:
                raise JiraIssueError(update_resp.text)

        # special case: the status could be the same while resolution is different.
        # in this case, raise an error.
        if not updated_resolution:
            primary_resolution = (primary_fields.get("resolution", {}) or {}).get("name", None)
            replica_resolution = (replica_fields.get("resolution", {}) or {}).get("name", None)
            if primary_resolution != replica_resolution:
                raise JiraIssueError("Resolutions differ: {primary} vs {replica}".format(
                    primary=primary_resolution, replica=replica_resolution
                ))

        if not made_changes:
            raise JiraIssueSkip("No changes to sync")

        return new_key if forwards else old_key

    def migrate_issue_by_key(self, old_key, idempotent=True):
        """
        Returns the new key, or None.
        """
        print("=== Migrating issue {}".format(old_key))
        issue = self.old_jira.get_issue(old_key)
        if not issue:
            raise JiraIssueError("Couldn't get issue by key: {}".format(old_key))

        new_key = None
        try:
            new_key, migrated = self.migrate_issue(issue, idempotent=idempotent)
        except JiraIssueSkip as jis:
            self.skipped(old_key)
            print("... Skipped {old}: {jis}\n".format(old=old_key, jis=jis))
        except JiraIssueError as jie:
            self.failed(old_key)
            print("... Couldn't migrate {old}: {jie}\n".format(old=old_key, jie=jie))
        else:
            assert new_key
            self.succeeded(old_key, new_key)
            if migrated:
                print("... Migrated {old} to {new}".format(old=old_key, new=new_key))
            else:
                print("... {old} was previously migrated to {new}".format(old=old_key, new=new_key))

        return new_key

    def migrate_by_jql(self, jql, limit=None, offset=0, idempotent=True):
        issues = self.old_jira.get_jql_issues(jql, offset=offset)
        self.also_run_issues(issue["key"] for issue in itertools.islice(issues, limit))
        self.migrate_all_issues(idempotent)

    def sync_by_jql(self, jql, limit=None, forwards=False):
        if forwards:
            jira = self.old_jira
        else:
            jira = self.new_jira
        issues = jira.get_jql_issues(jql)
        self.also_run_issues(issue["key"] for issue in itertools.islice(issues, limit))
        self.sync_all_issues(forwards=forwards)

    def migrate_by_file(self, key_file, limit=None, idempotent=True):
        stripped_lines = (line.strip() for line in key_file)
        nonblank_lines = (line for line in stripped_lines if line)
        key_generator = itertools.islice(nonblank_lines, limit)
        self.also_run_issues(key_generator)
        self.migrate_all_issues(idempotent)

    def sync_by_file(self, key_file, limit=None, forwards=False):
        stripped_lines = (line.strip() for line in key_file)
        nonblank_lines = (line for line in stripped_lines if line)
        key_generator = itertools.islice(nonblank_lines, limit)
        self.also_run_issues(key_generator)
        self.sync_all_issues(forwards=forwards)

    def migrate_all_issues(self, idempotent=True):
        for key in itertools.chain.from_iterable(self.issue_iterables):
            self.migrate_issue_by_key(key, idempotent=idempotent)

    def sync_all_issues(self, forwards=False):
        if forwards:
            new_or_old = "old_key"
        else:
            new_or_old = "new_key"

        for key in itertools.chain.from_iterable(self.issue_iterables):
            try:
                alt_key = self.sync_issue(**{new_or_old: key, "forwards": forwards})
            except JiraIssueSkip as jis:
                self.skipped(key)
                print("... Skipped {key}: {jis}\n".format(key=key, jis=jis))
            except JiraIssueError as jie:
                self.failed(key)
                print("... Couldn't migrate {key}: {jie}\n".format(key=key, jie=jie))
            else:
                self.succeeded(key, alt_key)
                print("... Synced {key} {direction} to {alt_key}".format(
                    key=key, alt_key=alt_key,
                    direction="forwards" if forwards else "backwards"
                ))


def parse_arguments(argv):
    parser = argparse.ArgumentParser(
        description="Migrate JIRA tickets",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--debug", default="")
    parser.add_argument("--jql",
        help="The JIRA JQL query to find issues to migrate",
    )
    parser.add_argument("-f", "--file",
        type=argparse.FileType("r"),
        help="File that lists issue keys, one per line",
    )
    parser.add_argument("--sync-forwards",
        action="store_true",
        help="Change new issues to match old issues",
    )
    parser.add_argument("--sync-backwards", "--sync",
        action="store_true", dest="sync_backwards",
        help="Change old issues to match new issues",
    )
    parser.add_argument("--write-failures", dest="failure_file",
        type=argparse.FileType("w"),
        help="Write failure keys to the given file, one per line",
    )
    parser.add_argument("--limit", type=int,
        help="Don't migrate more than this many issues",
    )
    parser.add_argument("--offset", type=int, default=0,
        help="Skip the first N issues",
    )
    parser.add_argument("--no-idempotent", dest="idempotent",
        action="store_const", const=False, default=True,
        help="Create new issues for already-migrated issues",
    )
    parser.add_argument("--private",
        action="store_const", const=True, default=False,
        help="Create all new issues as private",
    )

    args = parser.parse_args(argv[1:])

    args.debug = args.debug.split(",")

    if args.sync_forwards and args.sync_backwards:
        raise ConfigurationError("Cannot sync both ways")

    if not args.file and not args.jql:
        raise ConfigurationError("Must specify either JQL statement or keys file")
    if args.file and args.jql:
        raise ConfigurationError("Cannot specify both JQL statement and keys file")

    args.sync = bool(args.sync_forwards or args.sync_backwards)

    return args


def migrate(config, args):
    migrator = JiraMigrator(config, debug=args.debug, all_private=args.private)

    start = time.time()
    try:
        if args.file:
            migrator.migrate_by_file(
                args.file, limit=args.limit, idempotent=args.idempotent,
            )
        else:
            migrator.migrate_by_jql(
                args.jql, limit=args.limit, offset=args.offset, idempotent=args.idempotent,
            )
    except KeyboardInterrupt:
        print()
    end = time.time()

    print(
        "Migrated {success} issues, {failure} failures, {skip} skips "
        "in {duration:.1f} minutes".format(
            success=len(migrator.success), failure=len(migrator.failure),
            skip=len(migrator.skip), duration=(end - start)/60.0,
        )
    )
    print("Made {} requests to old JIRA, {} requests to new".format(
        migrator.old_jira.session.count, migrator.new_jira.session.count,
    ))

    if args.failure_file and migrator.failure:
        for failure_key in migrator.failure:
            args.failure_file.write(failure_key)
            args.failure_file.write("\n")

    return 0


def sync(config, args):
    migrator = JiraMigrator(config, debug=args.debug)

    start = time.time()
    try:
        if args.file:
            migrator.sync_by_file(
                args.file, limit=args.limit, forwards=args.sync_forwards,
            )
        else:
            migrator.sync_by_jql(
                args.jql, limit=args.limit, forwards=args.sync_forwards,
            )
    except KeyboardInterrupt:
        print()
    end = time.time()

    print(
        "Synced {success} issues, {failure} failures, {skip} skips "
        "in {duration:.1f} minutes".format(
            success=len(migrator.success), failure=len(migrator.failure),
            skip=len(migrator.skip), duration=(end - start)/60.0,
        )
    )
    print("Made {} requests to old JIRA, {} requests to new".format(
        migrator.old_jira.session.count, migrator.new_jira.session.count,
    ))

    if args.failure_file and migrator.failure:
        for failure_key in migrator.failure:
            args.failure_file.write(failure_key)
            args.failure_file.write("\n")

    return 0


def main(argv):
    config = SafeConfigParser()
    args = parse_arguments(argv)

    files_read = config.read("config.ini")
    if not files_read:
        print("Couldn't read config.ini")
        return 1

    if args.sync:
        return sync(config, args)
    else:
        return migrate(config, args)
