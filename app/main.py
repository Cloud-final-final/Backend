from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, LargeBinary
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import requests
import os
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

# Configuración
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Base de datos
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    hashed_password = Column(String)


class FileData(Base):
    __tablename__ = "files"
    id = Column(String, primary_key=True, index=True)
    owner = Column(String, index=True)
    filename = Column(String)
    content = Column(LargeBinary)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Modelos


class UserCreate(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.hashed_password):
        return user
    return None


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(
        User.username == user.username).first()
    if existing_user:
        raise HTTPException(
            status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(user.password)
    db.add(User(username=user.username, hashed_password=hashed_password))
    db.commit()
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logout")
def logout():
    return {"message": "Logout successful"}


@app.get("/users/me")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username}


@app.post("/upload")
def upload_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    file_data = FileData(id=str(datetime.utcnow().timestamp(
    )), owner=current_user.username, filename=file.filename, content=file.file.read())
    db.add(file_data)
    db.commit()
    return {"filename": file.filename, "message": "File uploaded successfully"}


@app.get("/files")
def get_user_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    files = db.query(FileData).filter(
        FileData.owner == current_user.username).all()
    return [{"id": file.id, "filename": file.filename} for file in files]


@app.get("/files/{file_id}")
def download_file(file_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    file = db.query(FileData).filter(FileData.id == file_id,
                                     FileData.owner == current_user.username).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    return {"filename": file.filename, "content": file.content}


class AskRequest(BaseModel):
    question: str


@app.post("/ask/{file_id}")
def ask_file(file_id: str, request: AskRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    file = db.query(FileData).filter(FileData.id == file_id,
                                     FileData.owner == current_user.username).first()
    if not file:
        raise HTTPException(
            status_code=404, detail="File not found or unauthorized access")

    text = file.content.decode("utf-8", errors="ignore")

    # Get OpenRouter API key from environment
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
    if not OPENROUTER_API_KEY:
        raise HTTPException(
            status_code=500, detail="OpenRouter API key not configured")

    # Make request to OpenRouter API
    response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": "meta-llama/llama-4-maverick:free",
            "messages": [
                {
                    "role": "system",
                    "content": f"You are a helpful assistant. Use the following context to answer the question:\n\n{text}"
                },
                {
                    "role": "user",
                    "content": request.question
                }
            ]
        }
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=500, detail="Error calling language model API")

    result = response.json()
    answer = result['choices'][0]['message']['content']

    return {"answer": answer}
