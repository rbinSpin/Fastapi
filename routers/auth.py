from datetime import datetime, timedelta
from typing import Annotated
from database import SessionLocal
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError, jwt
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse

router = APIRouter(
  prefix='/auth',
  tags=['auth']
)

class LoginForm:
  def __init__(self, request: Request):
    self.request: Request = request
    self.username: str | None = None
    self.password: str | None = None

  async def create_oauth_form(self):
    form = await self.request.form()
    self.username = form.get("email")
    self.password = form.get("password")


templates = Jinja2Templates(directory="templates")

SECRET_KEY = 'b50f918eadcaf6b10a8dbd52f6e4528611c9abadda89eb0d6fa3fe0ecc38b1f8'
ALGORITHM = 'HS256'


bcypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')


class CreateUserRequest(BaseModel):
  username: str
  email: str
  first_name: str
  last_name: str
  password: str
  role: str
  phone_number: str


class Token(BaseModel):
  access_token: str
  token_type: str


def get_db():
  db = SessionLocal()
  try:
    yield db
  finally:
    db.close()


db_dependency = Annotated[Session, Depends(get_db)]


def authenticate_user(username: str, password: str, db):
  user = db.query(Users).filter(Users.username == username).first()
  if not user:
    return False
  if not bcypt_context.verify(password, user.hashed_password):
    return False
  return user

def create_access_token(username: str, user_id: int,role: str, expires_delta: timedelta):

  encode = {'sub': username, 'id': user_id, 'role': role}
  expires = datetime.utcnow() + expires_delta
  encode.update({'exp': expires})
  return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(request: Request):
  try:
    token = request.cookies.get("access_token")
    if token is None:
      return None
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get('sub')
    user_id: int = payload.get('id')
    user_role: str = payload.get('role')
    if username is None or user_id is None:
      logout(request)
    return {'username': username, 'id': user_id, 'user_role': user_role}
  except JWTError:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND)


@router.post("/create/user", status_code=status.HTTP_201_CREATED)
async def create_user(create_user_request: CreateUserRequest, db: db_dependency):
  create_user_model = Users(
    email=create_user_request.email,
    username=create_user_request.username,
    first_name=create_user_request.first_name,
    last_name=create_user_request.last_name,
    hashed_password=bcypt_context.hash(create_user_request.password),
    role=create_user_request.role,
    is_active=True,
    phone_number=create_user_request.phone_number
  )

  db.add(create_user_model)
  db.commit()


# token
@router.post("/token", response_model=Token)
async def login_for_access_token(response: Response,form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
                                 db: db_dependency):
  user = authenticate_user(form_data.username, form_data.password, db)
  if not user:
    return False
  token_expires = timedelta(minutes=60)
  token = create_access_token(user.username, user.id, user.role, expires_delta=token_expires)

  response.set_cookie(key="access_token", value=token, httponly=True)
  
  return True
# @router.post("/token", response_model=Token)
# async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
#                                  db: db_dependency):
#     user = authenticate_user(form_data.username, form_data.password, db)
#     if not user:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
#                             detail='Could not validate user.')
#     token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))

#     return {'access_token': token, 'token_type': 'bearer'}


@router.get("/", response_class=HTMLResponse) 
async def authentication_page(request: Request):
  return templates.TemplateResponse("login.html", {"request": request})

@router.post("/", response_class=HTMLResponse)
async def login(request: Request, db: Session = Depends(get_db)):
  try:
    form = LoginForm(request)
    await form.create_oauth_form()
    response = RedirectResponse(url="/todos", status_code=status.HTTP_302_FOUND)

    validate_user_cookie = await login_for_access_token(response=response, form_data=form, db=db)

    if not validate_user_cookie:
      msg = 'incorrect Username or Password'
      return templates.TemplateResponse("login.html", {"request": request, "msg": msg})
    return response
  except:
    msg = "Unknown Error"
    return templates.TemplateResponse("login.html", {"request": request, "msg": msg})


@router.get("/logout")
async def logout(request: Request):
  msg = "Logout Successful"
  response = templates.TemplateResponse("login.html", {"request": request, "msg": msg})
  response.delete_cookie(key="access_token")
  return response


@router.get("/register", response_class=HTMLResponse) 
async def register(request: Request):
  return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register", response_class=HTMLResponse)
async def register_user(request: Request, email: str = Form(...), username: str = Form(...),
                        firstname: str = Form(...), lastname: str = Form(...),
                        password: str = Form(...), password2: str = Form(...),
                        db: Session = Depends(get_db)):

  validation1 = db.query(Users).filter(Users.username == username).first()
  validation2 = db.query(Users).filter(Users.email == email).first()

  if password != password2 or validation1 is not None or validation2 is not None:
    msg = "Invalid registeration request"
    return templates.TemplateResponse("register.html", {"request": request, "msg": msg})
  
  user_model = Users()
  user_model.username = username
  user_model.email = email
  user_model.first_name = firstname
  user_model.last_name = lastname

  user_model.hashed_password = bcypt_context.hash(password)
  user_model.is_active = True


  db.add(user_model)
  db.commit()

  msg = "User Successfully created"
  return templates.TemplateResponse("login.html", {"request": request, "msg": msg})