from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from passlib.apps import custom_app_context as pwd_context
import random, string

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'


class Category(Base):
    __tablename__ = 'category'


class Item(Base):
    __tablename__ = 'item'


engine = create_engine('sqlite:///usersWithOAuth.db')
Base.metadata.create_all(engine)
