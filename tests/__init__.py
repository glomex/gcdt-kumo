# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import os
import logging


def here(p):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), p))

logging.basicConfig()
