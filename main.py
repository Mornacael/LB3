from fastapi import FastAPI, HTTPException, Depends
from fastapi.params import Security
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.security import HTTPBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.hash import bcrypt

# Налаштування бази даних
SQLALCHEMY_DATABASE_URL = "sqlite:///./payments.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Налаштування для хешування паролів та JWT
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


# Моделі
class Client(Base):
    __tablename__ = "clients"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    accounts = relationship("Account", back_populates="owner")


class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    balance = Column(Float, default=0.0)
    blocked = Column(Boolean, default=False)
    owner_id = Column(Integer, ForeignKey("clients.id"))
    owner = relationship("Client", back_populates="accounts")
    credit_cards = relationship("CreditCard", back_populates="account")
    payments = relationship("Payment", back_populates="account")


class CreditCard(Base):
    __tablename__ = "credit_cards"
    id = Column(Integer, primary_key=True, index=True)
    card_number = Column(String, unique=True)
    expiration_date = Column(String)
    cvv = Column(String)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    account = relationship("Account", back_populates="credit_cards")


class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("accounts.id"))
    amount = Column(Float)
    account = relationship("Account", back_populates="payments")


class Admin(Base):
    __tablename__ = "admins"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


Base.metadata.create_all(bind=engine)

# Ініціалізація FastAPI
app = FastAPI()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_client(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        client = db.query(Client).filter(Client.username == username).first()
        if client is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return client
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/clients/")
def create_client(username: str, hashed_password: str,  db: Session = Depends(get_db)):
    client = Client(username = username, hashed_password = hashed_password)
    db.add(client)
    db.commit()
    db.refresh(client)
    return client


# Ендпоінти рахунків
@app.post("/accounts")
def create_account(client: Client = Depends(get_current_client), db: Session = Depends(get_db)):
    account = Account(owner_id=client.id)
    db.add(account)
    db.commit()
    return {"message": "Account created"}

@app.put("/accounts/{account_id}/block")
def block_account(account_id: int, client: Client = Depends(get_current_client), db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.id == account_id, Account.owner_id == client.id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    account.blocked = True
    db.commit()
    return {"message": "Account blocked"}




@app.post("/credit-cards/")
def create_credit_card(account_id: int, card_number: str, expiration_date: str, cvv: str,
                       db: Session = Depends(get_db)):
    card = CreditCard(account_id=account_id, card_number=card_number, expiration_date=expiration_date, cvv=cvv)
    db.add(card)
    db.commit()
    db.refresh(card)
    return card


@app.post("/payments/")
def make_payment(account_id: int, amount: float, db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    if account.blocked:
        raise HTTPException(status_code=403, detail="Account is blocked")
    if account.balance < amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    account.balance -= amount
    payment = Payment(account_id=account_id, amount=amount)
    db.add(payment)
    db.commit()
    db.refresh(payment)
    return payment


@app.put("/accounts/{account_id}/unblock")
def unblock_account(account_id: int, admin_id: int, db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.id == admin_id).first()
    if not admin:
        raise HTTPException(status_code=403, detail="Unauthorized action")
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    account.is_blocked = False
    db.commit()
    return {"message": "Account unblocked"}


@app.put("/accounts/{account_id}/deposit")
def deposit(account_id: int, amount: float, db: Session = Depends(get_db)):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    account.balance += amount
    db.commit()
    return {"message": "Account credited", "new_balance": account.balance}

@app.get("/clients/")
def get_clients(db: Session = Depends(get_db)):
    return db.query(Client).all()

@app.get("/accounts/")
def get_accounts(db: Session = Depends(get_db)):
    return db.query(Account).all()

@app.get("/credit-cards/")
def get_credit_cards(db: Session = Depends(get_db)):
    return db.query(CreditCard).all()

@app.get("/payments/")
def get_payments(db: Session = Depends(get_db)):
    return db.query(Payment).all()


# Допоміжні функції
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        admin = db.query(Admin).filter(Admin.username == username).first()
        if admin is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return admin
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Ендпоінт для реєстрації адміністратора
@app.post("/admin/register")
def register_admin(username: str, password: str, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(password)
    admin = Admin(username=username, hashed_password=hashed_password)
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return {"message": "Admin registered successfully"}


# Ендпоінт для отримання токена адміністратора
@app.post("/admin/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    admin = db.query(Admin).filter(Admin.username == form_data.username).first()
    if not admin or not verify_password(form_data.password, admin.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": admin.username})
    return {"access_token": access_token, "token_type": "bearer"}

security = HTTPBearer()

# Ендпоінти реєстрації та авторизації
@app.post("/clients")
def register_client(username: str, password: str, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(password)
    client = Client(username=username, hashed_password=hashed_password)
    db.add(client)
    db.commit()
    return {"message": "Client registered"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(Client).filter(Client.username == form_data.username).first() or \
           db.query(Admin).filter(Admin.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token({"sub": user.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
