#!/usr/bin/env python
import sys

from jira_migrate.issues import main

if __name__ == "__main__":
    sys.exit(main(sys.argv))
