## Detailed Documentation for Express.js Application Setup Script

### Overview

This setup script initializes an Express.js application with MongoDB integration, JWT authentication, and several middleware for security and development efficiency. It includes the creation of initial files, directories, environment configurations, and the installation of necessary dependencies.

### Table of Contents
1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [Environment Configuration](#environment-configuration)
4. [Key Scripts](#key-scripts)
5. [Middleware](#middleware)
6. [Controllers](#controllers)
7. [Models](#models)
8. [Routes](#routes)
9. [Testing](#testing)
10. [Running the Application](#running-the-application)
11. [API Documentation](#api-documentation)
12. [Security Considerations](#security-considerations)
13. [Additional Notes](#additional-notes)

### Prerequisites

Ensure you have the following installed before running the setup script:
- Node.js (>= 14.x)
- npm (Node Package Manager)
- MongoDB

### Project Structure

After running the script, your project directory will look like this:
```
my-express-app/
├── logs/
├── src/
│   ├── config/
│   │   ├── config.js
│   │   ├── validateEnv.js
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── homeController.js
│   ├── docs/
│   │   ├── swagger.js
│   ├── middleware/
│   │   ├── authenticate.js
│   │   ├── errorHandler.js
│   │   ├── logger.js
│   ├── models/
│   │   ├── user.js
│   ├── routes/
│   │   ├── index.js
│   ├── tests/
│   │   ├── index.test.js
│   ├── index.js
├── .env
├── .env.example
├── package.json
└── README.md
```

### Environment Configuration

The script creates `.env` and `.env.example` files for environment-specific configurations.

#### .env.example
```env
PORT=3000
NODE_ENV=development
MONGO_URI=mongodb://localhost:27017/my-express-app
JWT_SECRET=your_jwt_secret
CSRF_SECRET=your_csrf_secret
MAILER_EMAIL=user@example.com
MAILER_PASSWORD=password
```

**Explanation:**
- `PORT`: Port number on which the server will run.
- `NODE_ENV`: Environment setting (development, production, etc.).
- `MONGO_URI`: MongoDB connection string.
- `JWT_SECRET`: Secret key for signing JWT tokens.
- `CSRF_SECRET`: Secret key for CSRF protection.
- `MAILER_EMAIL` and `MAILER_PASSWORD`: Credentials for email sending.

### Key Scripts

#### src/index.js
Sets up the main Express server with middleware, security configurations, routes, and Socket.io integration.

**Key Points:**
- **Express Setup:** Initializes the Express app.
- **Middleware Integration:** Adds security, parsing, and other middleware.
- **Database Connection:** Connects to MongoDB.
- **Routes:** Defines the routes to be used in the application.
- **Error Handling:** Includes a basic error handler.
- **Socket.io:** Integrates Socket.io for real-time communication.

#### src/config/config.js
Handles environment variables and configuration.

**Key Points:**
- Loads environment variables using `dotenv`.
- Provides a central place to access configuration values.

#### src/config/validateEnv.js
Validates required environment variables.

**Key Points:**
- Ensures critical environment variables are set.
- Prevents application from running with missing configuration.

### Middleware

#### src/middleware/authenticate.js
JWT authentication middleware to protect routes.

**Key Points:**
- Checks for JWT in request headers.
- Verifies the token and extracts user information.
- Denies access if the token is invalid or missing.

#### src/middleware/errorHandler.js
Handles application errors and returns a JSON response.

**Key Points:**
- Catches errors and logs them.
- Sends a standardized JSON error response.

#### src/middleware/logger.js
Logs HTTP requests using Morgan.

**Key Points:**
- Uses Morgan for logging HTTP requests.
- Can be configured to log in various formats.

### Controllers

#### src/controllers/homeController.js
Handles requests to the home route.

**Example:**
```javascript
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
```

#### src/controllers/authController.js
Manages user authentication (login, register, refresh tokens).

**Key Points:**
- **Login:** Authenticates users and issues JWT tokens.
- **Register:** Creates new users with hashed passwords.
- **Refresh Token:** Issues new access tokens using refresh tokens stored in cookies.

**Example for Login:**
```javascript
const login = async (req, res) => {
  const { email, password } = req.body;
  // Authenticate user...
  res.json({ accessToken });
};
```

### Models

#### src/models/user.js
Defines the User model schema using Mongoose.

**Key Points:**
- Defines user fields (email, password).
- Uses Mongoose for schema definition and database interaction.

**Example:**
```javascript
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
```

### Routes

#### src/routes/index.js
Defines the application routes, connecting controllers to specific endpoints.

**Example:**
```javascript
const express = require('express');
const homeController = require('../controllers/homeController');
const authController = require('../controllers/authController');
const { authenticateJWT } = require('../middleware/authenticate');

const router = express.Router();

router.get('/', homeController.getHome);
router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/refresh-token', authController.refreshToken);

module.exports = router;
```

### Testing

#### src/tests/index.test.js
Contains a basic test case to ensure the home route returns 'Hello World!' with a 200 status code.

**Example:**
```javascript
const request = require('supertest');
const app = require('../index');

describe('GET /', () => {
  it('should return 200 OK', async () => {
    const response = await request(app).get('/');
    expect(response.status).toBe(200);
    expect(response.text).toBe('Hello World!');
  });
});
```

### Running the Application

1. **Install dependencies:**
   ```sh
   npm install
   ```

2. **Start the application in development mode:**
   ```sh
   npm run dev
   ```

3. **Run tests:**
   ```sh
   npm test
   ```

### API Documentation

The setup includes Swagger for API documentation.

**Access API documentation:**
- Navigate to `http://localhost:3000/api-docs` to view the automatically generated API documentation.

### Security Considerations

- **Environment Variables**: Store secrets and sensitive information in `.env` files and avoid committing them to version control.
- **Helmet**: Used for securing HTTP headers.
- **Rate Limiting**: Protects against brute-force attacks by limiting repeated requests.
- **CSRF Protection**: Enabled using `csurf` middleware.
- **MongoDB Sanitize**: Prevents MongoDB operator injection attacks.
- **JWT**: Used for stateless authentication.

### Additional Notes

- **Socket.io Integration**: The script includes setup for real-time communication using Socket.io.
- **API Documentation**: Swagger UI is set up for API documentation and can be accessed at `/api-docs`.
- **Project Scalability**: The script sets up a scalable directory structure and configuration suitable for large applications.

By following this detailed documentation, you should have a comprehensive understanding of the initial setup and structure of your Express.js application. This foundation can be further extended based on specific project requirements and future developments.
