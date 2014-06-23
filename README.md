Script to migrate JIRA issues from one instance to another.

# Configuration

To use this script, you must create a file called `config.ini` in the same
directory as where you run this script. This file follows [the standard INI
format](https://en.wikipedia.org/wiki/INI_file), and must contain at least the
following information:

    [origin]
    host=https://origin-jira.com
    username=admin
    password=password

    [destination]
    host=https://destination-jira.com
    username=admin
    password=password

## Ignored and Private Issues

You may not want to migrate all issues in your project -- or you may want to
migrate some issues under a different security level. To set this up, simply
use the `origin.ignore`, `origin.ignore-label`, `origin.private`, and
`origin.private-label` options in the config file.

The `ignore` option takes a comma-separated list of issue keys -- these issues
will not be migrated, and neither will any issues that depend on the issues
you've listed, such as subtasks. The `ignore-label` option specifies the name
of a label on a JIRA issue. If an issue is labeled with this name, then will be
treated exactly the same as if that issue key was listed in the `ignore` option.
Both `ignore` and `ignore-label` can be specified.

The `private` and `private-label` options work exactly the same as the `ignore`
and `ignore-label` options, but they *do* migrate the issue to the destination
instance. However, the migrated issues will be set up with the security level
that you specify in your config file using the `destination.private-id` option.
Note that due to a limitation of the JIRA REST API, you *must* specify the ID
of the security level that you wish private issues to be created with -- this
security level ID cannot be autodetected.
