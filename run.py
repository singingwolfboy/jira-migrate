#!/usr/bin/env python
import sys

from jira_migrate.migrate import main

if __name__ == "__main__":
    sys.exit(main(sys.argv))
