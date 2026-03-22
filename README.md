## FastAPI JWT Authentication

A reusable JWT authentication system for FastAPI projects.

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/MouadSadik/FastApi-Auth.git
cd fastapi-authentication
```

---

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Create `.env` file

Create a `.env` file in the root directory:

```env
SECRET_KEY=your_secret_key_here
ALGORITHM=HS256

ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8000
```

---

### 4. Run the server

```bash
fastapi dev
```

---

## Available Endpoints

* `POST /auth/register` → Register a new user
* `POST /auth/login` → Login (returns access token + sets refresh cookie)
* `POST /auth/refresh` → Refresh access token
* `POST /auth/logout` → Logout (revoke refresh token)

---

## Features

* JWT Access Token authentication
* Refresh Token with HTTP-only cookies
* Secure logout (token revocation)
* Environment-based configuration (`.env`)
* Clean and reusable architecture

---

## Notes

* Do NOT commit your `.env` file
* Make sure CORS is configured for frontend apps
* Use HTTPS in production (`secure=True` cookies)

---
