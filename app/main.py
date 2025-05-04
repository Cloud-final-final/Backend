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
import glob
from google.cloud import storage
import io
import uuid
from dotenv import load_dotenv


load_dotenv()

# Add these environment variables
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
GOOGLE_APPLICATION_CREDENTIALS = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

# Initialize GCS client (add after other initializations)
storage_client = storage.Client()
bucket = storage_client.bucket(GCS_BUCKET_NAME)

# Configuración
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
NFS_BASE_PATH = "/mnt/nfs"
OPENROUTER_API_KEY = "YYYY928fdea2b0a4ba2438XXXXf4aaf1b5XXXX97ba8eb792XXXX6d6da3d9159eb257fbd1e664XXXX"
OPENROUTER_API_KEY = str(OPENROUTER_API_KEY).replace(
    'XXXX', 'c').replace('YYYY', 'sk-or-v1-')

worker_url = "http://35.188.27.176:8001/process"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Base de datos
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
Base.metadata.create_all(bind=engine)


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
    # Create a unique ID for the document
    document_id = os.urandom(16).hex()

    # Define the GCS path: "documents/{username}/{document_id}/{filename}"
    gcs_path = f"documents/{current_user.username}/{document_id}/{file.filename}"

    # Read the file content
    file_content = await file.read()

    # Upload to GCS
    blob = bucket.blob(gcs_path)
    blob.upload_from_string(file_content)

    # Persist the document in the database
    new_document = Document(
        id=document_id,
        owner_username=current_user.username,
        filename=file.filename,
        file_path=gcs_path,  # Store the GCS path instead of NFS path
        embeddings=None  # The worker will fill this later
    )

    db.add(new_document)
    db.commit()
    db.refresh(new_document)

    # Notify worker to process the file
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
def ask_file(
    file_id: str,
    request: AskRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Find the document in the database
    document = db.query(Document).filter(
        Document.id == file_id,
        Document.owner_username == current_user.username
    ).first()

    # If document doesn't exist or doesn't belong to user, throw 404
    if not document:
        raise HTTPException(
            status_code=404, detail="Document not found or unauthorized access"
        )

    # Initialize context variable
    context = ""

    try:
        # Construct the base path for chunks in GCS
        base_gcs_path = document.file_path.rsplit('/', 1)[0]  # Remove filename
        chunk_prefix = f"{base_gcs_path}/chunks/chunk_"

        # List all blobs with the chunk prefix
        chunks = []
        blobs = list(bucket.list_blobs(prefix=f"{base_gcs_path}/chunks/"))

        # Sort blobs by name to maintain order
        sorted_blobs = sorted(blobs, key=lambda blob: blob.name)

        # Read each chunk and add to list
        for blob in sorted_blobs:
            if "chunk_" in blob.name:
                chunk_content = blob.download_as_text()
                chunks.append(chunk_content)

        # Join all chunks to form context
        if chunks:
            context = "\n\n".join(chunks)
            print(f"DEBUG: Successfully read {len(chunks)} chunks from GCS")
    except Exception as e:
        print(f"DEBUG: Error reading chunks from GCS: {e}")

    # If no chunks, try reading original file as fallback
    if not context:
        try:
            # Get the original file from GCS
            blob = bucket.blob(document.file_path)
            if blob.exists():
                context = blob.download_as_text()
                print(f"DEBUG: Successfully read original file from GCS")
        except Exception as e:
            print(f"DEBUG: Error reading original file from GCS: {e}")

    # If still no context, throw error
    if not context:
        print(
            f"DEBUG: No context could be generated. Document ID: {file_id}, Path: {document.file_path}")
        raise HTTPException(
            status_code=400, detail="No context could be generated from the document."
        )

    # Continue with OpenRouter API call as before
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
                    "content": f"You are a helpful assistant. Use the following context to answer the question:\n\n{context}\n\nUser's question: {request.question}"
                }
            ]
        }
    )

    # If OpenRouter responds with error, throw 500
    if response.status_code != 200:
        raise HTTPException(
            status_code=500, detail="Error calling language model API")

    # Parse JSON response and extract content generated by model
    result = response.json()
    answer = result['choices'][0]['message']['content']

    # Return generated response
    return {"answer": answer}
