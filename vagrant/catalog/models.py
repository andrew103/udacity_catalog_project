from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from passlib.apps import custom_app_context as pwd_context
import random, string

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'


class Proposal(Base):
    __tablename__ = 'proposal'


class Request(Base):
    __tablename__ = 'request'


class MealDate(Base):
    __tablename__ = 'mealdate'


engine = create_engine('sqlite:///usersWithOAuth.db')
Base.metadata.create_all(engine)
