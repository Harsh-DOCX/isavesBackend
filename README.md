# 🔐 iSaves - Secure Password Manager

iSaves is a modern password management application designed to help users securely store, organize, and manage their credentials in one place. It provides encrypted password storage, secure authentication, Google Sign-In support, account recovery options, and a clean user experience.

## 🚀 Features

### 🔑 Authentication

* User Registration & Login
* Secure Password Hashing using bcrypt
* JWT-based Authentication
* HTTP-Only Authentication Cookies
* Google OAuth Login
* Rate Limiting for Authentication Routes

### 🛡️ Security

* AES-256-GCM Password Encryption
* Encrypted Vault Storage
* Helmet Security Middleware
* CORS Protection
* Secure Session Management
* Password Recovery with Security Questions

### 📂 Password Vault

* Store Website Credentials
* Save Usernames & Passwords
* Add Personal Notes
* Retrieve Saved Credentials
* Delete Stored Entries

### 👤 User Profile

* Update Profile Information
* Manage Mobile Number
* Personal Information Storage
* Recovery Question Management

### 🌐 Smart Site Detection

* Website Domain Recognition
* Logo Fetching Support
* Fuzzy Matching for Popular Websites
* Automatic Domain Resolution

---

## 🛠️ Tech Stack

### Backend

* Node.js
* Express.js
* MongoDB
* Mongoose

### Security

* JWT
* bcryptjs
* AES-256-GCM Encryption
* Helmet
* Express Rate Limiter

### Authentication

* Google OAuth 2.0
* Cookie-based Sessions

---

## 📁 Project Structure

```bash
backend/
│
├── models/
├── routes/
├── middleware/
├── config/
├── .env
├── index.js
└── package.json
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory:

```env
PORT=8000

MONGODB_URI=your_mongodb_connection_string

JWT_SECRET=your_jwt_secret

ENCRYPTION_SECRET=your_encryption_secret

GOOGLE_CLIENT_ID=your_google_client_id

FRONTEND_ORIGIN=http://localhost:3000
```

---

## 📦 Installation

### Clone Repository

```bash
git clone https://github.com/your-username/isaves.git
cd isaves
```

### Install Dependencies

```bash
npm install
```

### Start Development Server

```bash
npm run dev
```

or

```bash
node index.js
```

---

## API Endpoints

### Authentication

| Method | Endpoint                  |
| ------ | ------------------------- |
| POST   | /api/auth/signup          |
| POST   | /api/auth/login           |
| POST   | /api/auth/google          |
| GET    | /api/auth/me              |
| PUT    | /api/auth/profile         |
| POST   | /api/auth/logout          |
| POST   | /api/auth/forgot-password |
| POST   | /api/auth/reset-password  |

### Vault

| Method | Endpoint            |
| ------ | ------------------- |
| GET    | /api/vault          |
| POST   | /api/vault          |
| DELETE | /api/vault/:entryId |

### Utilities

| Method | Endpoint        |
| ------ | --------------- |
| GET    | /api/health     |
| GET    | /api/site-image |

---

## Security Highlights

* Passwords are hashed using bcrypt before storage.
* Vault credentials are encrypted using AES-256-GCM.
* JWT authentication with secure cookies.
* Rate limiting protects against brute-force attacks.
* Security headers provided by Helmet.
* Sensitive data protected through environment variables.

---

## Future Enhancements

* Password Generator
* Password Strength Analysis
* Two-Factor Authentication (2FA)
* Vault Sharing
* Browser Extension
* Password Breach Detection
* Encrypted Cloud Backup

---

## Author

**Harsh Jadon**

BCA Student | Web Developer | React Developer

Skills:

* HTML
* CSS
* JavaScript
* React
* Node.js
* MongoDB
* Data Structures & Algorithms

---

⭐ If you like this project, consider giving it a star on GitHub!
