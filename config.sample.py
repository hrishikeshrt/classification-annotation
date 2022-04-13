#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration

@author: Hrishikesh Terdalkar
"""

###############################################################################

DATA_FILE = "data/data.csv"

# list of user ids with admin access
ADMIN_USERS = ["admin"]

# default classification labels
DEFAULT_LABELS = {
    "label-key": "label-name-display",
}

# generate a nice key using secrets.token_urlsafe()
SECRET_KEY = "not-so-secret-key"
HASH_SALT = "hash-salt"

# SQLAlchemy compatible database-uri
DATABASE_URI = "sqlite:///db/marathi.db"

###############################################################################
