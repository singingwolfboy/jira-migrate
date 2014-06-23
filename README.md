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
