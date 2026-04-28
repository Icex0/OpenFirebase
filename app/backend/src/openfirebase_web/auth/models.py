import uuid

from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID

from ..db import Base


class User(SQLAlchemyBaseUserTableUUID, Base):
    pass


UserId = uuid.UUID
