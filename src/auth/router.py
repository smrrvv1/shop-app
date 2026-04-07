from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from authx import AuthX, AuthXConfig, TokenPayload

from src.database import get_db
from src.auth.models import User
from src.auth.schemas import UserRegisterSchema


config = AuthXConfig(
    JWT_SECRET_KEY="test-secret-key",
    JWT_TOKEN_LOCATION=["headers"],
)

auth = AuthX(config=config)
security = HTTPBearer()

user_router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@user_router.post("/register", status_code=status.HTTP_201_CREATED)
def create_user(
    user_data: UserRegisterSchema,      # ← входные данные от пользователя
    db: Session = Depends(get_db)
):
    # 1. Проверка: существует ли уже пользователь с таким email
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Пользователь с таким email уже существует"
        )

    # 2. Создаём объект для сохранения в базу (SQLAlchemy модель)
    new_user = User(
        email=user_data.email,
        password=user_data.password,   # ← позже заменим на хэш!
        first_name="",                 # можно сделать опциональными позже
        last_name=""
    )

    # 3. Сохраняем в базу
    db.add(new_user)
    db.commit()
    db.refresh(new_user)               # обновляем объект, чтобы получить id и другие поля

    # 4. Создаём JWT-токен
    access_token = auth.create_access_token(uid=new_user.email)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "message": "Регистрация прошла успешно"
    }

@user_router.post("/login")
def login(
    email: str,           # принимаем email вместо username
    password: str,
    db: Session = Depends(get_db)
):
    # Ищем пользователя в базе по email
    user = db.query(User).filter(User.email == email).first()

    # Проверяем, существует ли пользователь и совпадает ли пароль
    if not user or user.password != password:
        raise HTTPException(
            status_code=401,
            detail="Неверный email или пароль"
        )

    # Создаём токен (используем email как идентификатор пользователя)
    access_token = auth.create_access_token(uid=user.email)

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


@user_router.get("/protected")
def protected(payload: TokenPayload = Depends(auth.access_token_required),
              credentials = Depends(security)):
    return {"message": payload.sub}