#!/bin/bash

# Check if Node.js is installed
if ! [ -x "$(command -v node)" ]; then
  echo 'Error: Node.js is not installed. Please install Node.js (https://nodejs.org/)' >&2
  exit 1
fi

# Check if npm is installed
if ! [ -x "$(command -v npm)" ]; then
  echo 'Error: npm is not installed. Please install npm (https://www.npmjs.com/)' >&2
  exit 1
fi

# Check if directory already exists
if [ -d "my-express-app" ]; then
  echo "Error: Directory my-express-app already exists. Please choose a different name or remove the existing directory." >&2
  exit 1
fi

# Create a new directory for the project
mkdir my-express-app
cd my-express-app

# Initialize npm project
npm init -y

# Install Express.js and other dependencies
npm install express body-parser dotenv helmet cors mongoose jsonwebtoken bcryptjs joi swagger-ui-express express-rate-limit

# Install development dependencies
npm install --save-dev nodemon jest supertest eslint

# Create directories and initial files
mkdir -p src/routes src/config src/middleware src/controllers src/tests src/models src/docs
touch src/index.js src/routes/index.js src/config/config.js src/middleware/logger.js src/middleware/errorHandler.js src/controllers/homeController.js src/controllers/authController.js src/tests/index.test.js src/models/user.js src/config/validateEnv.js src/docs/swagger.js

# Create a .env file (template)
touch .env .env.example
echo "PORT=3000" >> .env.example
echo "NODE_ENV=development" >> .env.example
echo "MONGO_URI=mongodb://localhost:27017/my-express-app" >> .env.example
echo "JWT_SECRET=your_jwt_secret" >> .env.example
cp .env.example .env

# Add basic Express server setup to src/index.js
cat <<EOL > src/index.js
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const morgan = require('morgan');
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
const port = config.port;

// Database connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch((err) => {
  console.error('Error connecting to MongoDB:', err.message);
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
app.use(morgan('dev'));
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

module.exports = app;
EOL

# Add basic route setup to src/routes/index.js
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

# Add basic controller setup to src/controllers/homeController.js
cat <<EOL > src/controllers/homeController.js
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
EOL

# Add auth controller to src/controllers/authController.js
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
    res.status(500).send('Error logging in');
  }
};

module.exports = { register, login };
EOL

# Add user model to src/models/user.js
cat <<EOL > src/models/user.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOL

# Add environment variable validation to src/config/validateEnv.js
cat <<EOL > src/config/validateEnv.js
const Joi = require('joi');

const envSchema = Joi.object({
  PORT: Joi.number().default(3000),
  NODE_ENV: Joi.string().valid('development', 'production').default('development'),
  MONGO_URI: Joi.string().required(),
  JWT_SECRET: Joi.string().required(),
}).unknown().required();

const { error, value } = envSchema.validate(process.env);
if (error) {
  throw new Error(\`Environment validation error: \${error.message}\`);
}

module.exports = value;
EOL

# Add Swagger documentation setup to src/docs/swagger.js
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
              'application/json': {
                example: 'Hello World!',
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
        },
      },
    },
    '/register': {
      post: {
        summary: 'Register route',
        requestBody: {
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
            description: 'Error registering user',
          },
        },
      },
    },
  },
};

module.exports = swaggerDocument;
EOL

# Add basic test setup to src/tests/index.test.js
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

# Add ESLint configuration
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

# Add start, dev, test, and lint scripts to package.json
npm set-script start "node src/index.js"
npm set-script dev "nodemon src/index.js"
npm set-script test "jest --coverage"
npm set-script lint "eslint 'src/**/*.js'"

# Create a README.md file
cat <<EOL > README.md
# My Express App

This is a simple Express.js project.

## Getting Started

### Prerequisites

- Node.js
- npm

### Installing

1. Clone the repo
   \`\`\`
   git clone https://github.com/yourusername/my-express-app.git
   \`\`\`
2. Install NPM packages
   \`\`\`
   npm install
   \`\`\`

### Running the server

- Development mode
  \`\`\`
  npm run dev
  \`\`\`

- Production mode
  \`\`\`
  npm start
  \`\`\`

### Running tests

\`\`\`
npm test
\`\`\`

### Linting

\`\`\`
npm run lint
\`\`\`

## Built With

- [Express](https://expressjs.com/) - The web framework used
- [Nodemon](https://nodemon.io/) - Used for development to automatically restart the server
- [Jest](https://jestjs.io/) - Testing framework
- [Supertest](https://github.com/visionmedia/supertest) - HTTP assertions for testing
- [ESLint](https://eslint.org/) - Linting utility
- [Helmet](https://helmetjs.github.io/) - Security middleware
- [Cors](https://github.com/expressjs/cors) - Middleware to enable CORS
- [Mongoose](https://mongoosejs.com/) - MongoDB object modeling tool
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) - JWT authentication
- [bcryptjs](https://github.com/dcodeIO/bcrypt.js) - Password hashing
- [joi](https://joi.dev/) - Object schema validation
- [Swagger](https://swagger.io/) - API documentation tool
- [express-rate-limit](https://www.npmjs.com/package/express-rate-limit) - Rate limiting middleware

## Authors

- **Your Name** - *Initial work* - [YourGitHub](https://github.com/yourusername)
EOL

# Create a .gitignore file
cat <<EOL > .gitignore
node_modules/
.env
coverage/
EOL

# Create a basic GitHub Actions CI configuration
mkdir -p .github/workflows
cat <<EOL > .github/workflows/node.js.yml
name: Node.js CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:

    runs-on: ubuntu-latest

    strategy:
      matrix:
        node-version: [14, 16, 18]

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
echo "Express.js starter pack installation complete. Run 'npm start' to start the server, 'npm run dev' to start the server with Nodemon, 'npm test' to run tests, or 'npm run lint' to lint the code."
