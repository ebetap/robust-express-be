#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Check if Node.js is installed
if ! command_exists node; then
  echo 'Error: Node.js is not installed. Please install Node.js (https://nodejs.org/)' >&2
  exit 1
fi

# Check if npm is installed
if ! command_exists npm; then
  echo 'Error: npm is not installed. Please install npm (https://www.npmjs.com/)' >&2
  exit 1
fi

# Check if MongoDB is installed
if ! command_exists mongod; then
  echo 'Error: MongoDB is not installed or not in PATH. Please install MongoDB (https://www.mongodb.com/)' >&2
  exit 1
fi

# Function to handle directory existence
create_directory() {
  if [ -d "$1" ]; then
    echo "Error: Directory $1 already exists. Please choose a different name or remove the existing directory." >&2
    exit 1
  fi
  mkdir -p "$1"
}

# Create a new directory for the project
create_directory "my-express-app"
cd "my-express-app" || exit 1

# Initialize npm project
npm init -y

# Install dependencies
npm install express body-parser dotenv helmet cors mongoose jsonwebtoken bcryptjs joi swagger-ui-express express-rate-limit

# Install dev dependencies
npm install --save-dev nodemon jest supertest eslint

# Create project structure
create_directory "src"
create_directory "src/routes"
create_directory "src/config"
create_directory "src/middleware"
create_directory "src/controllers"
create_directory "src/tests"
create_directory "src/models"
create_directory "src/docs"

# Create initial files
touch src/index.js src/routes/index.js src/config/config.js \
      src/middleware/logger.js src/middleware/errorHandler.js \
      src/controllers/homeController.js src/controllers/authController.js \
      src/tests/index.test.js src/models/user.js src/config/validateEnv.js \
      src/docs/swagger.js

# Create .env files
touch .env .env.example
echo "PORT=3000" >>.env.example
echo "NODE_ENV=development" >>.env.example
echo "MONGO_URI=mongodb://localhost:27017/my-express-app" >>.env.example
echo "JWT_SECRET=your_jwt_secret" >>.env.example
cp .env.example .env

# Populate src/index.js with basic setup
cat <<EOL > src/index.js
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const routes = require('./routes');
const { logger } = require('./middleware/logger');
const errorHandler = require('./middleware/errorHandler');
const config = require('./config/config');
const swaggerDocument = require('./docs/swagger');
const validateEnv = require('./config/validateEnv');

dotenv.config();
validateEnv();

const app = express();
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
app.use(helmet());
app.use(cors());
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
}));

// Middleware
app.use(bodyParser.json());
app.use(logger);

// API documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Routes
app.use('/', routes);

// Error handling middleware
app.use(errorHandler);

app.listen(port, () => {
  console.log(\`Server is running on port \${port}\`);
});
EOL

# Populate src/routes/index.js with basic route setup
cat <<EOL > src/routes/index.js
const express = require('express');
const homeController = require('../controllers/homeController');
const authController = require('../controllers/authController');

const router = express.Router();

router.get('/', homeController.getHome);
router.post('/login', authController.login);
router.post('/register', authController.register);

module.exports = router;
EOL

# Populate src/controllers/homeController.js with basic controller setup
cat <<EOL > src/controllers/homeController.js
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
EOL

# Populate src/controllers/authController.js with basic auth controller setup
cat <<EOL > src/controllers/authController.js
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const register = async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered successfully');
  } catch (err) {
    console.error('Error registering user:', err.message);
    res.status(500).send('Error registering user');
  }
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).send('Invalid credentials');
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    console.error('Error logging in:', err.message);
    res.status(500).send('Error logging in');
  }
};

module.exports = { register, login };
EOL

# Populate src/models/user.js with basic user model setup
cat <<EOL > src/models/user.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOL

# Populate src/config/validateEnv.js with environment variable validation setup
cat <<EOL > src/config/validateEnv.js
const Joi = require('joi');

const envSchema = Joi.object({
  PORT: Joi.number().default(3000),
  NODE_ENV: Joi.string().valid('development', 'production').default('development'),
  MONGO_URI: Joi.string().required(),
  JWT_SECRET: Joi.string().required(),
}).unknown().required();

const { error, value: envVars } = envSchema.validate(process.env);
if (error) {
  throw new Error(\`Config validation error: \${error.message}\`);
}

module.exports = envVars;
EOL

# Populate src/docs/swagger.js with basic Swagger documentation setup
cat <<EOL > src/docs/swagger.js
const swaggerDocument = {
  openapi: '3.0.0',
  info: {
    title: 'My Express API',
    version: '1.0.0',
    description: 'API documentation for My Express API',
  },
  paths: {
    '/': {
      get: {
        summary: 'Home route',
        responses: {
          200: {
            description: 'Successful response',
            content: {
              'text/plain': {
                schema: {
                  type: 'string',
                  example: 'Hello World!',
                },
              },
            },
          },
        },
      },
    },
    '/login': {
      post: {
        summary: 'Login route',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: { type: 'string' },
                  password: { type: 'string' },
                },
                required: ['username', 'password'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Successful login',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    token: { type: 'string' },
                  },
                },
              },
            },
          },
          401: {
            description: 'Invalid credentials',
          },
          500: {
            description: 'Internal Server Error',
          },
        },
      },
    },
    '/register': {
      post: {
        summary: 'Register route',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: { type: 'string' },
                  password: { type: 'string' },
                },
                required: ['username', 'password'],
              },
            },
          },
        },
        responses: {
          201: {
            description: 'User registered successfully',
          },
          500: {
            description: 'Internal Server Error',
          },
        },
        },
      },
    },
  },
};

module.exports = swaggerDocument;
EOL

# Populate src/middleware/logger.js with basic logger middleware setup
cat <<EOL > src/middleware/logger.js
const logger = (req, res, next) => {
  console.log(\`\${new Date().toISOString()} - \${req.method} \${req.originalUrl} - \${req.ip}\`);
  next();
};

module.exports = { logger };
EOL

# Populate src/middleware/errorHandler.js with basic error handling middleware setup
cat <<EOL > src/middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  console.error(\`Error: \${err.message}\`);
  res.status(500).send('Internal Server Error');
};

module.exports = errorHandler;
EOL

# Populate src/tests/index.test.js with basic test setup
cat <<EOL > src/tests/index.test.js
const request = require('supertest');
const app = require('../index');
const mongoose = require('mongoose');

afterAll(async () => {
  await mongoose.connection.close();
});

describe('GET /', () => {
  it('should return Hello World!', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
    expect(res.text).toBe('Hello World!');
  });
});

describe('POST /register', () => {
  it('should register a new user', async () => {
    const res = await request(app)
      .post('/register')
      .send({ username: 'testuser', password: 'testpassword' });
    expect(res.statusCode).toEqual(201);
  });
});

describe('POST /login', () => {
  it('should login an existing user', async () => {
    await request(app)
      .post('/register')
      .send({ username: 'testuser', password: 'testpassword' });
    const res = await request(app)
      .post('/login')
      .send({ username: 'testuser', password: 'testpassword' });
    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('token');
  });
});
EOL

# Create ESLint configuration file
cat <<EOL > .eslintrc.json
{
  "env": {
    "browser": true,
    "es2021": true,
    "node": true,
    "jest": true
  },
  "extends": "eslint:recommended",
  "parserOptions": {
    "ecmaVersion": 12,
    "sourceType": "module"
  },
  "rules": {
    "indent": ["error", 2],
    "linebreak-style": ["error", "unix"],
    "quotes": ["error", "single"],
    "semi": ["error", "always"]
  }
}
EOL

# Update package.json scripts for start, dev, test, and lint
npm set-script start "node src/index.js"
npm set-script dev "nodemon src/index.js"
npm set-script test "jest --coverage"
npm set-script lint "eslint 'src/**/*.js'"

# Create README.md file
cat <<EOL > README.md
# My Express App

This is a simple Express.js project.

## Getting Started

### Prerequisites

- Node.js
- npm
- MongoDB

### Installation

1. Clone the repository:
   \`\`\`
   git clone https://github.com/yourusername/my-express-app.git
   cd my-express-app
   \`\`\`

2. Install dependencies:
   \`\`\`
   npm install
   \`\`\`

3. Set up environment variables:
   - Create a \`.env\` file based on \`.env.example\`.
   - Adjust MongoDB URI and JWT Secret in \`.env\`.

### Running the Server

- Development mode (with nodemon):
  \`\`\`
  npm run dev
  \`\`\`

- Production mode:
  \`\`\`
  npm start
  \`\`\`

### Running Tests

\`\`\`
npm test
\`\`\`

### Linting

\`\`\`
npm run lint
\`\`\`

## Built With

- [Express](https://expressjs.com/) - Fast, unopinionated, minimalist web framework for Node.js
- [MongoDB](https://www.mongodb.com/) - NoSQL database
- [Mongoose](https://mongoosejs.com/) - MongoDB object modeling tool
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - JSON Web Token implementation for Node.js
- [bcryptjs](https://github.com/dcodeIO/bcrypt.js) - Password hashing library
- [Joi](https://joi.dev/) - Object schema validation
- [Swagger UI Express](https://www.npmjs.com/package/swagger-ui-express) - Swagger UI middleware for Express
- [express-rate-limit](https://www.npmjs.com/package/express-rate-limit) - Rate limiting middleware for Express
- [supertest](https://github.com/visionmedia/supertest) - HTTP assertions for testing
- [Jest](https://jestjs.io/) - JavaScript Testing Framework
- [nodemon](https://nodemon.io/) - Monitor for any changes in your source and automatically restart your server

## Authors

- **Your Name** - [YourGitHub](https://github.com/yourusername)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
EOL

# Create .gitignore file
cat <<EOL > .gitignore
node_modules/
.env
coverage/
EOL

# Create GitHub Actions CI configuration
mkdir -p .github/workflows
cat <<EOL > .github/workflows/node.js.yml
name: Node.js CI

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  build:

    runs-on: ubuntu-latest

    strategy:
      matrix:
        node-version:
          - 14.x
          - 16.x
          - 18.x

    steps:
      - uses: actions/checkout@v2
      - name: Use Node.js \${{ matrix.node-version }}
        uses: actions/setup-node@v2
        with:
          node-version: \${{ matrix.node-version }}
      - run: npm install
      - run: npm run lint
      - run: npm test
EOL

# Completion message
echo "Express.js starter pack installation complete."
echo "Run 'npm start' to start the server, 'npm run dev' to start the server with nodemon,"
echo "'npm test' to run tests, or 'npm run lint' to lint the code."
