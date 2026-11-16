"""Entry point for the Django URLconf fixture.

NOT A RUNNABLE PROJECT. It exists so the route extractor can be tested against
a URLconf tree with includes, regex patterns, class-based views and a DRF
router, which one application fixture could not cover between them.
"""

import os
import sys


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
