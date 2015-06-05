import datetime
from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
 
Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'category'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'user_id'      : self.user_id,
       }
 
class Item(Base):
    __tablename__ = 'item'


    id = Column(Integer, primary_key = True)
    name =Column(String(80), nullable = False)
    description = Column(String(250))
    price = Column(String(8))
    picture = Column(String(250))
    category_id = Column(Integer,ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer,ForeignKey('user.id'))
    user = relationship(User)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'           : self.id,
           'name'         : self.name,
           'description'  : self.description,
           'price'        : self.price,
           'picture'      : self.picture,
           'category_id'  : self.category_id,
           'user_id'      : self.user_id,
       }

       
       
class Nonce(Base):
    __tablename__ = 'nonce'
    
    id = Column(Integer, primary_key = True)
    state = Column(String(64))
    nonce = Column(String(512))

"""
CREATE VIEW item_counts as 
select category.id as cat, count(item.id) as items
FROM Category
LEFT JOIN Item on category.id = item.category_id GROUP BY category.id;
"""
       
       
engine = create_engine('sqlite:///catalog.db')

Base.metadata.create_all(engine)
