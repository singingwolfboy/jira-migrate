Script to migrate JIRA issues from one instance to another.

To use this script, you will need to create a `config.ini` file with the following
structure:

    [origin]
    host=https://origin-jira.com
    username=admin
    password=password

    [destination]
    host=https://destination-jira.com
    username=admin
    password=password
