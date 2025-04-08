from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, LargeBinary, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import requests
import os
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import shutil

load_dotenv()

# Configuración
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
NFS_BASE_PATH = "/mnt/nfs"
OPENROUTER_API_KEY = "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"

worker_url = "http://10.128.0.4:8001/process"

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

    documents = relationship("Document", back_populates="owner")


class Document(Base):
    __tablename__ = "documents"
    id = Column(String, primary_key=True, index=True)
    owner_username = Column(String, ForeignKey("users.username"))
    filename = Column(String)
    file_path = Column(Text)
    embeddings = Column(JSON)

    owner = relationship("User", back_populates="documents")


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
async def upload_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    nfs_base_path = "/mnt/nfs"  # Ruta montada
    user_folder = os.path.join(NFS_BASE_PATH, current_user.username)
    os.makedirs(user_folder, exist_ok=True)

    # Crear carpeta basada en el nombre del archivo (sin extensión)
    file_base_name = os.path.splitext(file.filename)[0]
    document_folder = os.path.join(user_folder, file_base_name)
    os.makedirs(document_folder, exist_ok=True)

    # Ruta final para guardar el archivo original
    file_location = os.path.join(document_folder, file.filename)

    # Guardar el archivo
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Persistir el documento en la base de datos
    new_document = Document(
        id=os.urandom(16).hex(),
        owner_username=current_user.username,
        filename=file.filename,
        file_path=document_folder,  # <-- Guardamos la carpeta, no el archivo
        embeddings=None  # Los embeddings los rellenará el worker después
    )

    db.add(new_document)
    db.commit()
    db.refresh(new_document)
    # IP interna de tu worker
    payload = {"document_id": new_document.id}

    try:
        response = requests.post(worker_url, json=payload, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to notify worker: {e}")

    return {"filename": file.filename, "message": "File uploaded successfully"}


@app.get("/files")
def get_user_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    documents = db.query(Document).filter(
        Document.owner_username == current_user.username).all()
    return [{"id": document.id, "filename": document.filename} for document in documents]


@app.get("/files/{file_id}")
def download_file(file_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    document = db.query(Document).filter(
        Document.id == file_id, Document.owner_username == current_user.username).first()
    if not document:
        raise HTTPException(status_code=404, detail="File not found")
    return {"filename": document.filename, "content": "File content to be added from NFS"}


class AskRequest(BaseModel):
    question: str


@app.post("/ask/{file_id}")
def ask_file(file_id: str, request: AskRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Get document from database
    document = db.query(Document).filter(
        Document.id == file_id,
        Document.owner_username == current_user.username
    ).first()

    if not document:
        raise HTTPException(
            status_code=404, detail="Document not found or unauthorized access")

    # Check if embeddings are available
    if not document.embeddings:
        raise HTTPException(
            status_code=400, detail="Document embeddings are not yet available. Please wait for processing to complete.")

    # Get OpenRouter API key from environment

    # Prepare context from document embeddings
    # The embeddings should contain the document text chunks
    context = ""
    if isinstance(document.embeddings, dict) and "text_chunks" in document.embeddings:
        context = "\n\n".join(document.embeddings["text_chunks"])
    elif isinstance(document.embeddings, list) and len(document.embeddings) > 0:
        # If embeddings is a list of chunks with text
        chunks = [chunk.get("text", "") for chunk in document.embeddings if isinstance(
            chunk, dict) and "text" in chunk]
        context = "\n\n".join(chunks)

    # If no context could be extracted from embeddings, try to read the file directly
    if not context:
        try:
            file_path = os.path.join(document.file_path, document.filename)
            if os.path.exists(file_path):
                with open(file_path, "r", errors="ignore") as f:
                    context = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            # Continue with empty context if file can't be read

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
                    "role": "user",
                    "content": f"You are a helpful assistant. Use the following context to answer the question:\n\n{context}"
                },
            ]
        }
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=500, detail="Error calling language model API")

    result = response.json()
    answer = result['choices'][0]['message']['content']

    return {"answer": answer}
