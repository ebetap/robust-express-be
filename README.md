## Documentation for Express.js Application Setup Script

### Overview

This script sets up a basic Express.js application with MongoDB integration, JWT authentication, and other common middleware for security and development efficiency. The setup includes initial file creation, directory structure, environment configuration, and installation of necessary dependencies.

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

### Key Scripts

#### src/index.js
Sets up the main Express server with middleware, security configurations, routes, and Socket.io integration.

#### src/config/config.js
Handles environment variables and configuration.

#### src/config/validateEnv.js
Validates required environment variables.

### Middleware

#### src/middleware/authenticate.js
JWT authentication middleware to protect routes.

#### src/middleware/errorHandler.js
Handles application errors and returns a JSON response.

#### src/middleware/logger.js
Logs HTTP requests using Morgan.

### Controllers

#### src/controllers/homeController.js
Handles requests to the home route.

#### src/controllers/authController.js
Manages user authentication (login, register, refresh tokens).

### Models

#### src/models/user.js
Defines the User model schema using Mongoose.

### Routes

#### src/routes/index.js
Defines the application routes, connecting controllers to specific endpoints.

### Testing

#### src/tests/index.test.js
Contains a basic test case to ensure the home route returns 'Hello World!' with a 200 status code.

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

### Example Usage

1. **Initialize and start the server:**
   ```sh
   npm init -y
   ./setup_script.sh
   npm run dev
   ```

2. **Test the API endpoints using tools like Postman or curl:**
   - **Home Route:**
     ```sh
     curl http://localhost:3000/
     ```

   - **Register User:**
     ```sh
     curl -X POST http://localhost:3000/register -H "Content-Type: application/json" -d '{"email": "user@example.com", "password": "password"}'
     ```

   - **Login User:**
     ```sh
     curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"email": "user@example.com", "password": "password"}'
     ```

3. **Access API documentation:**
   Open a web browser and navigate to `http://localhost:3000/api-docs`.

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

By following this documentation, you should have a comprehensive understanding of the initial setup and structure of your Express.js application. This foundation can be further extended based on specific project requirements.
