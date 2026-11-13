import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

# Engine configuration with sqlite and postgres driver compatibility
connect_args = {}
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    # SQLAlchemy 2.0 defaults postgresql:// to psycopg (psycopg3).
    # If psycopg is missing but psycopg2 is present, adapt connection string.
    try:
        import psycopg  # noqa: F401
    except ImportError:
        db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()

