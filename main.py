from fastapi import FastAPI, APIRouter, HTTPException, Depends
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get('JWT_SECRET', 'tempo-secret-key-change-in-prod')
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 72

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def lifespan(app: FastAPI):
    await db.users.create_index("email", unique=True)
    await db.users.create_index("id", unique=True)
    await db.tasks.create_index([("user_id", 1), ("next_due", 1)])
    await db.tasks.create_index([("is_shared", 1), ("next_due", 1)])
    await db.tasks.create_index("id", unique=True)
    await db.tags.create_index([("user_id", 1), ("name", 1)], unique=True)
    await db.tags.create_index("id", unique=True)
    await db.invitations.create_index("token", unique=True)
    await db.invitations.create_index("id", unique=True)
    await db.invitations.create_index("email")
    logger.info("Database indexes created")
    yield
    client.close()


app = FastAPI(lifespan=lifespan)
api_router = APIRouter(prefix="/api")

# ─── Models ───

class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    created_at: str
    is_admin: bool = False

class TokenResponse(BaseModel):
    token: str
    user: UserResponse

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = ""
    interval_days: float = 7
    tags: List[str] = []
    next_due: Optional[str] = None
    is_shared: bool = False

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    interval_days: Optional[float] = None
    tags: Optional[List[str]] = None
    next_due: Optional[str] = None

class TaskResponse(BaseModel):
    id: str
    user_id: str
    title: str
    description: str
    interval_days: float
    tags: List[str]
    next_due: str
    created_at: str
    updated_at: str
    completion_count: int
    last_completed: Optional[str] = None
    is_shared: bool = False
    owner_name: str = ""

class CompletionRequest(BaseModel):
    feedback: str  # too_early, just_right, too_late

class TagCreate(BaseModel):
    name: str
    color: Optional[str] = "#F97316"

class TagResponse(BaseModel):
    id: str
    user_id: str
    name: str
    color: str

class InviteCreate(BaseModel):
    email: str

class InviteResponse(BaseModel):
    id: str
    email: str
    token: str
    created_by: str
    created_by_name: str
    created_at: str
    used: bool
    used_at: Optional[str] = None

class AdminUserResponse(BaseModel):
    id: str
    name: str
    email: str
    created_at: str
    is_admin: bool

class InviteRegister(BaseModel):
    token: str
    name: str
    password: str

# ─── Auth Helpers ───

def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(authorization: str = None):
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization
    if authorization.startswith("Bearer "):
        token = authorization[7:]
    
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ─── Dependency ───

from fastapi import Header

async def auth_dependency(authorization: str = Header(None)):
    return await get_current_user(authorization)

async def admin_dependency(authorization: str = Header(None)):
    user = await get_current_user(authorization)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ─── Auth Routes ───

@api_router.get("/auth/signup-allowed")
async def signup_allowed():
    count = await db.users.count_documents({})
    return {"allowed": count == 0}

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(data: UserCreate):
    user_count = await db.users.count_documents({})
    if user_count > 0:
        raise HTTPException(status_code=403, detail="Registration is closed. You need an invitation from an admin.")
    
    existing = await db.users.find_one({"email": data.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "id": user_id,
        "name": data.name,
        "email": data.email.lower(),
        "password_hash": pwd_context.hash(data.password),
        "created_at": now,
        "is_admin": True,
    }
    await db.users.insert_one(user_doc)
    
    token = create_token(user_id)
    return TokenResponse(
        token=token,
        user=UserResponse(id=user_id, name=data.name, email=data.email.lower(), created_at=now, is_admin=True)
    )

@api_router.get("/auth/invite/{invite_token}")
async def validate_invite(invite_token: str):
    invite = await db.invitations.find_one({"token": invite_token}, {"_id": 0})
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid invitation link")
    if invite.get("used"):
        raise HTTPException(status_code=400, detail="This invitation has already been used")
    return {"email": invite["email"], "valid": True}

@api_router.post("/auth/register-invite", response_model=TokenResponse)
async def register_invite(data: InviteRegister):
    invite = await db.invitations.find_one({"token": data.token}, {"_id": 0})
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid invitation link")
    if invite.get("used"):
        raise HTTPException(status_code=400, detail="This invitation has already been used")
    
    existing = await db.users.find_one({"email": invite["email"]})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if data.password and len(data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    user_doc = {
        "id": user_id,
        "name": data.name,
        "email": invite["email"],
        "password_hash": pwd_context.hash(data.password),
        "created_at": now,
        "is_admin": False,
    }
    await db.users.insert_one(user_doc)
    
    await db.invitations.update_one(
        {"token": data.token},
        {"$set": {"used": True, "used_at": now}}
    )
    
    token = create_token(user_id)
    return TokenResponse(
        token=token,
        user=UserResponse(id=user_id, name=data.name, email=invite["email"], created_at=now, is_admin=False)
    )

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email.lower()}, {"_id": 0})
    if not user or not pwd_context.verify(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_token(user["id"])
    return TokenResponse(
        token=token,
        user=UserResponse(id=user["id"], name=user["name"], email=user["email"], created_at=user["created_at"], is_admin=user.get("is_admin", False))
    )

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(user=Depends(auth_dependency)):
    return UserResponse(id=user["id"], name=user["name"], email=user["email"], created_at=user["created_at"], is_admin=user.get("is_admin", False))

# ─── Task Routes ───

@api_router.get("/tasks", response_model=List[TaskResponse])
async def get_tasks(user=Depends(auth_dependency)):
    query = {"$or": [{"user_id": user["id"]}, {"is_shared": True}]}
    tasks = await db.tasks.find(query, {"_id": 0}).sort("next_due", 1).to_list(1000)
    return tasks

@api_router.post("/tasks", response_model=TaskResponse)
async def create_task(data: TaskCreate, user=Depends(auth_dependency)):
    task_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    if data.next_due:
        next_due = data.next_due
    else:
        next_due = (datetime.now(timezone.utc) + timedelta(days=data.interval_days)).isoformat()
    
    task_doc = {
        "id": task_id,
        "user_id": user["id"],
        "title": data.title,
        "description": data.description or "",
        "interval_days": data.interval_days,
        "tags": data.tags,
        "next_due": next_due,
        "created_at": now,
        "updated_at": now,
        "completion_count": 0,
        "last_completed": None,
        "is_shared": data.is_shared,
        "owner_name": user["name"],
    }
    await db.tasks.insert_one(task_doc)
    return {k: v for k, v in task_doc.items() if k != "_id"}

@api_router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str, user=Depends(auth_dependency)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("user_id") != user["id"] and not task.get("is_shared"):
        raise HTTPException(status_code=403, detail="Access denied")
    return task

@api_router.put("/tasks/{task_id}", response_model=TaskResponse)
async def update_task(task_id: str, data: TaskUpdate, user=Depends(auth_dependency)):
    task = await db.tasks.find_one({"id": task_id})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("user_id") != user["id"] and not task.get("is_shared"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    update_data = {}
    if data.title is not None:
        update_data["title"] = data.title
    if data.description is not None:
        update_data["description"] = data.description
    if data.interval_days is not None:
        update_data["interval_days"] = data.interval_days
    if data.tags is not None:
        update_data["tags"] = data.tags
    if data.next_due is not None:
        update_data["next_due"] = data.next_due
    
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.tasks.update_one({"id": task_id}, {"$set": update_data})
    updated = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    return updated

@api_router.delete("/tasks/{task_id}")
async def delete_task(task_id: str, user=Depends(auth_dependency)):
    task = await db.tasks.find_one({"id": task_id})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("user_id") != user["id"] and not task.get("is_shared"):
        raise HTTPException(status_code=403, detail="Access denied")
    await db.tasks.delete_one({"id": task_id})
    return {"message": "Task deleted"}

@api_router.post("/tasks/{task_id}/toggle-shared", response_model=TaskResponse)
async def toggle_shared(task_id: str, user=Depends(auth_dependency)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    is_own = task.get("user_id") == user["id"]
    is_shared = task.get("is_shared", False)
    if not is_own and not is_shared:
        raise HTTPException(status_code=403, detail="Access denied")
    new_shared = not is_shared
    update_fields = {
        "is_shared": new_shared,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if new_shared:
        update_fields["owner_name"] = user["name"]
    if not new_shared and not is_own:
        update_fields["user_id"] = user["id"]
        update_fields["owner_name"] = user["name"]
    await db.tasks.update_one({"id": task_id}, {"$set": update_fields})
    updated = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    return updated

@api_router.post("/tasks/{task_id}/complete", response_model=TaskResponse)
async def complete_task(task_id: str, data: CompletionRequest, user=Depends(auth_dependency)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.get("user_id") != user["id"] and not task.get("is_shared"):
        raise HTTPException(status_code=403, detail="Access denied")
    
    current_interval = task["interval_days"]
    
    if data.feedback == "too_early":
        new_interval = round(current_interval * 1.25, 1)
    elif data.feedback == "too_late":
        new_interval = max(1, round(current_interval * 0.75, 1))
    else:
        new_interval = current_interval
    
    now = datetime.now(timezone.utc)
    new_next_due = (now + timedelta(days=new_interval)).isoformat()
    
    update_data = {
        "interval_days": new_interval,
        "next_due": new_next_due,
        "last_completed": now.isoformat(),
        "completion_count": task["completion_count"] + 1,
        "updated_at": now.isoformat(),
    }
    
    await db.tasks.update_one({"id": task_id}, {"$set": update_data})
    
    # Log completion
    log_doc = {
        "id": str(uuid.uuid4()),
        "task_id": task_id,
        "user_id": user["id"],
        "completed_at": now.isoformat(),
        "feedback": data.feedback,
        "previous_interval": current_interval,
        "new_interval": new_interval,
    }
    await db.completion_logs.insert_one(log_doc)
    
    updated = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    return updated

# ─── Tag Routes ───

@api_router.get("/tags", response_model=List[TagResponse])
async def get_tags():
    tags = await db.tags.find().to_list(100)
    return tags

@api_router.post("/tags", response_model=TagResponse)
async def create_tag(data: TagCreate, user=Depends(auth_dependency)):
    existing = await db.tags.find_one({"name": data.name})
    if existing:
        raise HTTPException(status_code=400, detail="Tag already exists")
    
    tag_id = str(uuid.uuid4())
    tag_doc = {
        "id": tag_id,
        "user_id": user["id"],
        "name": data.name,
        "color": data.color or "#F97316",
    }
    await db.tags.insert_one(tag_doc)
    return {k: v for k, v in tag_doc.items() if k != "_id"}

@api_router.delete("/tags/{tag_id}")
async def delete_tag(tag_id: str, user=Depends(auth_dependency)):
    result = await db.tags.delete_one({"id": tag_id, "user_id": user["id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Tag not found, or you don't have permission to delete it")
    return {"message": "Tag deleted"}

# ─── Admin Routes ───

@api_router.get("/admin/users", response_model=List[AdminUserResponse])
async def admin_list_users(user=Depends(admin_dependency)):
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).to_list(1000)
    return [AdminUserResponse(
        id=u["id"], name=u["name"], email=u["email"],
        created_at=u["created_at"], is_admin=u.get("is_admin", False)
    ) for u in users]

@api_router.delete("/admin/users/{user_id}")
async def admin_delete_user(user_id: str, user=Depends(admin_dependency)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    target = await db.users.find_one({"id": user_id})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    await db.users.delete_one({"id": user_id})
    shared_tasks = await db.tasks.find({"user_id": user_id, "is_shared": {"$eq": True}}).to_list(1000)
    shared_tags = set()
    for task in shared_tasks:
        shared_tags.update(map(lambda tag: tag["name"], task.get("tags", [])))
    await db.tasks.delete_many({"user_id": user_id, "is_shared": {"$ne": True}})
    await db.tags.delete_many({"user_id": user_id, "name": {"$nin": list(shared_tags)}})
    return {"message": "User deleted"}

@api_router.put("/admin/users/{user_id}/toggle-admin", response_model=AdminUserResponse)
async def admin_toggle_admin(user_id: str, user=Depends(admin_dependency)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot change your own admin status")
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    new_admin = not target.get("is_admin", False)
    await db.users.update_one({"id": user_id}, {"$set": {"is_admin": new_admin}})
    return AdminUserResponse(
        id=target["id"], name=target["name"], email=target["email"],
        created_at=target["created_at"], is_admin=new_admin
    )

@api_router.post("/admin/invite", response_model=InviteResponse)
async def admin_create_invite(data: InviteCreate, user=Depends(admin_dependency)):
    existing_user = await db.users.find_one({"email": data.email.lower()})
    if existing_user:
        raise HTTPException(status_code=400, detail="A user with this email already exists")
    existing_invite = await db.invitations.find_one({"email": data.email.lower(), "used": False})
    if existing_invite:
        raise HTTPException(status_code=400, detail="An active invitation already exists for this email")
    
    invite_id = str(uuid.uuid4())
    invite_token = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    invite_doc = {
        "id": invite_id,
        "email": data.email.lower(),
        "token": invite_token,
        "created_by": user["id"],
        "created_by_name": user["name"],
        "created_at": now,
        "used": False,
        "used_at": None,
    }
    await db.invitations.insert_one(invite_doc)
    return {k: v for k, v in invite_doc.items() if k != "_id"}

@api_router.get("/admin/invitations", response_model=List[InviteResponse])
async def admin_list_invitations(user=Depends(admin_dependency)):
    invitations = await db.invitations.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return invitations

@api_router.delete("/admin/invitations/{invite_id}")
async def admin_revoke_invitation(invite_id: str, user=Depends(admin_dependency)):
    invite = await db.invitations.find_one({"id": invite_id})
    if not invite:
        raise HTTPException(status_code=404, detail="Invitation not found")
    if invite.get("used"):
        raise HTTPException(status_code=400, detail="Cannot revoke a used invitation")
    await db.invitations.delete_one({"id": invite_id})
    return {"message": "Invitation revoked"}

# ─── Health ───

@api_router.get("/health")
async def health():
    return {"status": "ok"}

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

    
