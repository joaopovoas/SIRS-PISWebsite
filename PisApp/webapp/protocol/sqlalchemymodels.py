from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.types import Integer, Text, String, BigInteger, Float, DateTime
from sqlalchemy import Column
import uuid

Base = declarative_base()


class Useralchemy(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(97), nullable=False)
    cardinfo = Column(String(600), nullable=False)
    infosalt = Column(String(50), nullable=False)
    role = Column(String(50), default="standard", nullable=False)
    token = Column(String(60))
    timestamp = Column(DateTime)


class Transactionalchemy(Base):
    __tablename__ = 'transaction'
    id = Column(Integer, primary_key=True)
    transactionID = Column(String(97), unique=True, nullable=False)
    price = Column(Float, nullable=False)
    currency = Column(String(97), nullable=False)
    bank = Column(String(97), nullable=False)
    paidbyemail = Column(String(100), default="UNPAID", nullable=False)



def getAlchemySession():
    engine = create_engine(
        'mysql://root:password@' + "172.18.1.4" + '/testpis',
        echo=True)

    # Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()
    return session
