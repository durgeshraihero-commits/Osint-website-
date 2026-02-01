"""
DarkBoxes Web Platform Backend API
Handles authentication, user management, credits, and payment processing
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import os
import secrets
import hashlib
import httpx
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
import jwt
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# Configuration
class Config:
    # MongoDB
    MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
    DATABASE_NAME = "darkboxes_web"
    
    # JWT
    JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
    JWT_ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days
    
    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    
    # DarkBoxes Bot API
    DARKBOXES_API_URL = os.getenv("DARKBOXES_API_URL", "https://relay-wzlz.onrender.com/api/v1")
    
    # Payment Gateway (Razorpay)
    RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
    RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
    
    # Credits Pricing
    CREDIT_PACKAGES = {
        "starter": {"credits": 100, "price": 499, "name": "Starter Pack"},
        "professional": {"credits": 500, "price": 999, "name": "Professional Pack"},
        "enterprise": {"credits": -1, "price": 2999, "name": "Enterprise Pack"}  # -1 = unlimited
    }

config = Config()

# Initialize FastAPI
app = FastAPI(
    title="DarkBoxes Web API",
    description="Backend API for DarkBoxes Intelligence Platform",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database
db_client = None
db = None

@app.on_event("startup")
async def startup_db():
    global db_client, db
    db_client = AsyncIOMotorClient(config.MONGODB_URI)
    db = db_client[config.DATABASE_NAME]
    print(f"✅ Connected to MongoDB: {config.DATABASE_NAME}")

@app.on_event("shutdown")
async def shutdown_db():
    if db_client:
        db_client.close()
        print("✅ Closed MongoDB connection")

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    payload = verify_token(token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Models
class GoogleLoginRequest(BaseModel):
    token: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    picture: Optional[str]
    credits: int
    plan: str
    created_at: datetime

class SearchRequest(BaseModel):
    query: str
    search_type: str = "general"  # general, email, phone, username, etc.

class APIKeyCreate(BaseModel):
    name: str
    environment: str
    rate_limit: int
    description: Optional[str] = ""

class PurchaseRequest(BaseModel):
    package: str  # starter, professional, enterprise
    payment_method: str = "razorpay"

# Helper Functions
def generate_api_key(user_id: str) -> str:
    """Generate unique API key"""
    timestamp = int(datetime.utcnow().timestamp())
    random_part = secrets.token_hex(16)
    data = f"{user_id}:{timestamp}:{random_part}"
    api_key = hashlib.sha256(data.encode()).hexdigest()
    return f"dk_live_{api_key}"

async def deduct_credits(user_id: str, amount: int = 1) -> bool:
    """Deduct credits from user account"""
    result = await db.users.update_one(
        {"_id": user_id, "credits": {"$gte": amount}},
        {"$inc": {"credits": -amount}}
    )
    return result.modified_count > 0

async def add_credits(user_id: str, amount: int) -> bool:
    """Add credits to user account"""
    result = await db.users.update_one(
        {"_id": user_id},
        {"$inc": {"credits": amount}}
    )
    return result.modified_count > 0

# Routes

@app.get("/")
async def root():
    return {
        "service": "DarkBoxes Web API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.post("/auth/google", response_model=Dict[str, Any])
async def google_login(request: GoogleLoginRequest):
    """Authenticate user with Google OAuth"""
    try:
        # Verify Google token
        idinfo = id_token.verify_oauth2_token(
            request.token,
            google_requests.Request(),
            config.GOOGLE_CLIENT_ID
        )
        
        email = idinfo['email']
        name = idinfo.get('name', '')
        picture = idinfo.get('picture', '')
        google_id = idinfo['sub']
        
        # Check if user exists
        user = await db.users.find_one({"email": email})
        
        if not user:
            # Create new user
            user_id = f"user_{secrets.token_hex(8)}"
            user = {
                "_id": user_id,
                "email": email,
                "name": name,
                "picture": picture,
                "google_id": google_id,
                "credits": 10,  # Welcome credits
                "plan": "free",
                "created_at": datetime.utcnow(),
                "last_login": datetime.utcnow(),
            }
            await db.users.insert_one(user)
        else:
            # Update last login
            user_id = user["_id"]
            await db.users.update_one(
                {"_id": user_id},
                {"$set": {"last_login": datetime.utcnow()}}
            )
        
        # Create access token
        access_token = create_access_token({"user_id": user_id, "email": email})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user_id,
                "email": email,
                "name": name,
                "picture": picture,
                "credits": user.get("credits", 0),
                "plan": user.get("plan", "free")
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")

@app.get("/user/me", response_model=UserResponse)
async def get_user_profile(user: dict = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "id": user["_id"],
        "email": user["email"],
        "name": user.get("name", ""),
        "picture": user.get("picture", ""),
        "credits": user.get("credits", 0),
        "plan": user.get("plan", "free"),
        "created_at": user.get("created_at", datetime.utcnow())
    }

@app.post("/api-keys/create")
async def create_api_key(
    key_data: APIKeyCreate,
    user: dict = Depends(get_current_user)
):
    """Create new API key for user"""
    api_key = generate_api_key(user["_id"])
    
    key_doc = {
        "_id": f"key_{secrets.token_hex(8)}",
        "api_key": api_key,
        "user_id": user["_id"],
        "name": key_data.name,
        "environment": key_data.environment,
        "rate_limit": key_data.rate_limit,
        "description": key_data.description,
        "created_at": datetime.utcnow(),
        "last_used": None,
        "usage_count": 0,
        "active": True
    }
    
    await db.api_keys.insert_one(key_doc)
    
    return {
        "success": True,
        "api_key": api_key,
        "details": {
            "name": key_data.name,
            "environment": key_data.environment,
            "rate_limit": key_data.rate_limit
        }
    }

@app.get("/api-keys/list")
async def list_api_keys(user: dict = Depends(get_current_user)):
    """List all API keys for user"""
    keys = await db.api_keys.find({"user_id": user["_id"]}).to_list(length=100)
    
    return {
        "keys": [
            {
                "id": key["_id"],
                "name": key["name"],
                "api_key": key["api_key"],
                "environment": key["environment"],
                "rate_limit": key["rate_limit"],
                "usage_count": key.get("usage_count", 0),
                "created_at": key["created_at"],
                "last_used": key.get("last_used"),
                "active": key.get("active", True)
            }
            for key in keys
        ]
    }

@app.post("/search")
async def perform_search(
    search_data: SearchRequest,
    user: dict = Depends(get_current_user)
):
    """Perform intelligence search using DarkBoxes API"""
    
    # Check credits
    if user.get("credits", 0) < 1 and user.get("plan") != "enterprise":
        raise HTTPException(
            status_code=402,
            detail="Insufficient credits. Please purchase more credits to continue."
        )
    
    # Get user's DarkBoxes API key
    api_keys = await db.api_keys.find_one({
        "user_id": user["_id"],
        "active": True
    })
    
    if not api_keys:
        raise HTTPException(
            status_code=400,
            detail="No active API key found. Please create an API key first."
        )
    
    try:
        # Call DarkBoxes API
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{config.DARKBOXES_API_URL}/search",
                json={
                    "query": search_data.query,
                    "search_type": search_data.search_type
                },
                headers={
                    "Authorization": f"Bearer {api_keys['api_key']}"
                },
                timeout=60.0
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Deduct credits (only for non-enterprise users)
                if user.get("plan") != "enterprise":
                    await deduct_credits(user["_id"], 1)
                
                # Log search
                await db.search_history.insert_one({
                    "user_id": user["_id"],
                    "query": search_data.query,
                    "search_type": search_data.search_type,
                    "status": "success",
                    "credits_used": 1,
                    "timestamp": datetime.utcnow(),
                    "result_summary": result.get("data", {})
                })
                
                return {
                    "success": True,
                    "data": result.get("data"),
                    "credits_remaining": user.get("credits", 0) - 1
                }
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"DarkBoxes API error: {response.text}"
                )
                
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Search timeout. Please try again.")
    except Exception as e:
        # Log failed search
        await db.search_history.insert_one({
            "user_id": user["_id"],
            "query": search_data.query,
            "search_type": search_data.search_type,
            "status": "failed",
            "credits_used": 0,
            "timestamp": datetime.utcnow(),
            "error": str(e)
        })
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@app.get("/search/history")
async def get_search_history(
    limit: int = 50,
    user: dict = Depends(get_current_user)
):
    """Get user's search history"""
    history = await db.search_history.find(
        {"user_id": user["_id"]}
    ).sort("timestamp", -1).limit(limit).to_list(length=limit)
    
    return {
        "searches": [
            {
                "query": item["query"],
                "type": item["search_type"],
                "status": item["status"],
                "credits_used": item.get("credits_used", 0),
                "timestamp": item["timestamp"]
            }
            for item in history
        ]
    }

@app.post("/credits/purchase")
async def purchase_credits(
    purchase: PurchaseRequest,
    user: dict = Depends(get_current_user)
):
    """Purchase credits package"""
    
    package = config.CREDIT_PACKAGES.get(purchase.package)
    if not package:
        raise HTTPException(status_code=400, detail="Invalid package")
    
    # In production, integrate with Razorpay or Stripe here
    # For now, simulate payment
    
    # Create payment order
    order = {
        "_id": f"order_{secrets.token_hex(8)}",
        "user_id": user["_id"],
        "package": purchase.package,
        "amount": package["price"],
        "credits": package["credits"],
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    
    await db.orders.insert_one(order)
    
    # Return payment details (Razorpay integration point)
    return {
        "order_id": order["_id"],
        "amount": package["price"],
        "currency": "INR",
        "package": package["name"],
        "credits": package["credits"],
        "razorpay_key": config.RAZORPAY_KEY_ID,
        "callback_url": "/credits/verify"
    }

@app.post("/credits/verify")
async def verify_payment(
    order_id: str,
    payment_id: str,
    signature: str,
    user: dict = Depends(get_current_user)
):
    """Verify payment and add credits"""
    
    # In production, verify Razorpay signature here
    # For now, simulate successful payment
    
    order = await db.orders.find_one({"_id": order_id, "user_id": user["_id"]})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    # Add credits
    credits_to_add = order["credits"]
    if credits_to_add > 0:  # Not unlimited
        await add_credits(user["_id"], credits_to_add)
    else:
        # Update to enterprise plan
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"plan": "enterprise"}}
        )
    
    # Update order status
    await db.orders.update_one(
        {"_id": order_id},
        {
            "$set": {
                "status": "completed",
                "payment_id": payment_id,
                "completed_at": datetime.utcnow()
            }
        }
    )
    
    return {
        "success": True,
        "message": "Payment verified and credits added",
        "credits_added": credits_to_add if credits_to_add > 0 else "unlimited"
    }

@app.get("/stats")
async def get_user_stats(user: dict = Depends(get_current_user)):
    """Get user statistics"""
    
    # Total searches
    total_searches = await db.search_history.count_documents({"user_id": user["_id"]})
    
    # Searches this month
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_searches = await db.search_history.count_documents({
        "user_id": user["_id"],
        "timestamp": {"$gte": month_start}
    })
    
    # Success rate
    successful = await db.search_history.count_documents({
        "user_id": user["_id"],
        "status": "success"
    })
    success_rate = (successful / total_searches * 100) if total_searches > 0 else 0
    
    # Active API keys
    active_keys = await db.api_keys.count_documents({
        "user_id": user["_id"],
        "active": True
    })
    
    return {
        "credits": user.get("credits", 0),
        "plan": user.get("plan", "free"),
        "total_searches": total_searches,
        "monthly_searches": monthly_searches,
        "success_rate": round(success_rate, 1),
        "active_api_keys": active_keys
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
