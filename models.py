#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Apr 04 14:08:09 2022

@author: Hrishikesh Terdalkar
"""

###############################################################################

from sqlalchemy import Column, Integer, String, ForeignKey, Index
from sqlalchemy.orm import relationship, backref

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

###############################################################################
# Create database connection object

db = SQLAlchemy()

###############################################################################
# Corpus Database Models


class User(UserMixin, db.Model):
    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    hash = Column(String(255), nullable=False)


class Sentence(db.Model):
    id = Column(Integer, primary_key=True)
    headword = Column(String(255), nullable=False, index=True)
    text = Column(String(255), nullable=False)


class Label(db.Model):
    id = Column(Integer, primary_key=True)
    short = Column(String(255), nullable=False)
    label = Column(String(255), nullable=False)


class Annotation(db.Model):
    id = Column(Integer, primary_key=True)
    sentence_id = Column(Integer, ForeignKey("sentence.id"), nullable=False)
    annotator_id = Column(Integer, ForeignKey("user.id"), nullable=False)
    label_id = Column(Integer, ForeignKey("label.id"), nullable=False)
    comment = Column(String(255))

    annotator = relationship(
        "User", backref=backref("annotations", lazy="joined")
    )
    sentence = relationship(
        "Sentence", backref=backref("annotations", lazy="joined")
    )
    label = relationship(
        "Label", backref=backref("annotations", lazy="joined")
    )
    __table_args__ = (
        Index(
            "annotation_sentence_id_annotator_id",
            "sentence_id",
            "annotator_id",
            unique=True,
        ),
    )
