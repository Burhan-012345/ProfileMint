from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import os

# Use the correct path for the database
basedir = os.path.abspath(os.path.dirname(__file__))
database_path = os.path.join(basedir, 'instance', 'database.db')

# Create the instance directory if it doesn't exist
os.makedirs(os.path.dirname(database_path), exist_ok=True)

# Create the database engine
engine = create_engine(f'sqlite:///{database_path}')
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    # Import models to ensure they are registered with Base
    from models import User, Resume, OTP
    Base.metadata.create_all(bind=engine)