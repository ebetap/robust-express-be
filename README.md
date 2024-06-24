## Documentation for Express.js Application Setup Script

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

**Full Code Example:**
```javascript
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const csurf = require('csurf');
const mongoSanitize = require('express-mongo-sanitize');
const compression = require('compression');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const nodemailer = require('nodemailer');
const socketIo = require('socket.io');
const http = require('http');
const path = require('path');
const routes = require('./routes');
const { logger } = require('./middleware/logger');
const errorHandler = require('./middleware/errorHandler');
const config = require('./config/config');
const swaggerDocument = require('./docs/swagger');
const validateEnv = require('./config/validateEnv');
const helmetCsp = require('helmet-csp');

dotenv.config();
validateEnv();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const port = config.PORT || 3000;

// Database connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB');
})
.catch((err) => {
  console.error('Error connecting to MongoDB:', err.message);
  process.exit(1);
});

// Security middlewares
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(helmetCsp({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com'],
  },
}));
app.use(cors());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
}));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(logger);
app.use(errorHandler);
app.use(express.static(path.join(__dirname, 'public')));

// Enable gzip compression
app.use(compression());

// Enable request logging
app.use(morgan('combined'));

// Prevent MongoDB Operator Injection and XSS
app.use(mongoSanitize());

// CSRF Protection
app.use(csurf({ cookie: true }));

// API documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Routes
app.use('/', routes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Socket.io implementation
io.on('connection', (socket) => {
  console.log('A user connected');
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
```

#### src/config/config.js
Handles environment variables and configuration.

**Full Code Example:**
```javascript
const dotenv = require('dotenv');

dotenv.config();

module.exports = {
  PORT: process.env.PORT,
  MONGO_URI: process.env.MONGO_URI,
  JWT_SECRET: process.env.JWT_SECRET,
  CSRF_SECRET: process.env.CSRF_SECRET,
  MAILER_EMAIL: process.env.MAILER_EMAIL,
  MAILER_PASSWORD: process.env.MAILER_PASSWORD,
};
```

#### src/config/validateEnv.js
Validates required environment variables.

**Full Code Example:**
```javascript
const dotenv = require('dotenv');
const joi = require('joi');

dotenv.config();

const envSchema = joi.object({
  PORT: joi.number().default(3000),
  NODE_ENV: joi.string().valid('development', 'production').default('development'),
  MONGO_URI: joi.string().required(),
  JWT_SECRET: joi.string().required(),
  CSRF_SECRET: joi.string().required(),
  MAILER_EMAIL: joi.string().email().required(),
  MAILER_PASSWORD: joi.string().required(),
}).unknown();

const { error } = envSchema.validate(process.env);

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

module.exports = () => {};
```

### Middleware

#### src/middleware/authenticate.js
JWT authentication middleware to protect routes.

**Full Code Example:**
```javascript
const jwt = require('jsonwebtoken');
const config = require('../config/config');

const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error authenticating JWT:', error.message);
    return res.status(403).json({ message: 'Invalid token' });
  }
};

module.exports = { authenticateJWT };
```

#### src/middleware/errorHandler.js
Handles application errors and returns a JSON response.

**Full Code Example:**
```javascript
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
};

module.exports = errorHandler;
```

#### src/middleware/logger.js
Logs HTTP requests using Morgan.

**Full Code Example:**
```javascript
const morgan = require('morgan');

const logger = morgan('combined');

module.exports = { logger };
```

### Controllers

#### src/controllers/homeController.js
Handles requests to the home route.

**Full Code Example:**
```javascript
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
```

#### src/controllers/authController.js
Manages user authentication (login, register, refresh tokens).

**Full Code Example:**
```javascript
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const config = require('../config/config');

const login = async
