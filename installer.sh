#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to create directory if not exists
create_directory() {
  if [ -d "$1" ]; then
    echo "Directory '$1' already exists. Skipping creation."
  else
    mkdir -p "$1"
    echo "Created directory: $1"
  fi
}

# Function to create file if not exists
create_file() {
  if [ ! -f "$1" ]; then
    touch "$1"
    echo "Created file: $1"
  else
    echo "File '$1' already exists. Skipping creation."
  fi
}

# Function to initialize npm project if not already initialized
initialize_npm_project() {
  if [ ! -f package.json ]; then
    npm init -y
    echo "Initialized npm project."
  fi
}

# Function to install dependencies
install_dependencies() {
  npm install express body-parser dotenv helmet cors mongoose jsonwebtoken bcryptjs joi swagger-ui-express express-rate-limit --save
}

# Function to install dev dependencies
install_dev_dependencies() {
  npm install --save-dev nodemon jest supertest eslint
}

# Function to set up project structure
setup_project_structure() {
  create_directory "src"
  create_directory "src/routes"
  create_directory "src/config"
  create_directory "src/middleware"
  create_directory "src/controllers"
  create_directory "src/tests"
  create_directory "src/models"
  create_directory "src/docs"
}

# Function to populate initial files
populate_initial_files() {
  create_file "src/index.js"
  create_file "src/routes/index.js"
  create_file "src/config/config.js"
  create_file "src/middleware/logger.js"
  create_file "src/middleware/errorHandler.js"
  create_file "src/controllers/homeController.js"
  create_file "src/controllers/authController.js"
  create_file "src/tests/index.test.js"
  create_file "src/models/user.js"
  create_file "src/config/validateEnv.js"
  create_file "src/docs/swagger.js"
}

# Function to set up environment files
setup_environment_files() {
  create_file ".env"
  create_file ".env.example"

  if [ ! -s .env.example ]; then
    echo "PORT=3000" >> .env.example
    echo "NODE_ENV=development" >> .env.example
    echo "MONGO_URI=mongodb://localhost:27017/my-express-app" >> .env.example
    echo "JWT_SECRET=your_jwt_secret" >> .env.example
    echo "Created file: .env.example"
  else
    echo "File '.env.example' already exists and is not empty. Skipping population."
  fi

  if [ ! -s .env ]; then
    cp .env.example .env
    echo "Created file: .env"
  else
    echo "File '.env' already exists and is not empty. Skipping population."
  fi
}

# Function to set up initial Express app configuration
setup_express_app() {
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
}

# Function to set up initial routes
setup_initial_routes() {
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
}

# Function to set up initial home controller
setup_home_controller() {
  cat <<EOL > src/controllers/homeController.js
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
EOL
}

# Function to set up initial auth controller
setup_auth_controller() {
  cat <<EOL > src/controllers/authController.js
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

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
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (err) {
    console.error('Error logging in:', err.message);
    res.status(500).send('Error logging in');
  }
};

module.exports = { register, login };
EOL
}

# Function to set up initial user model
setup_user_model() {
  cat <<EOL > src/models/user.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOL
}

# Function to set up initial environment validation
setup_env_validation() {
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
}

# Function to set up initial Swagger documentation
setup_swagger_docs() {
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
                  example: {
                    token: 'your_jwt_token_here',
                  },
                },
              },
            },
          },
          400: {
            description: 'Bad request',
          },
          401: {description: 'Unauthorized',
        },
        500: {
          description: 'Internal Server Error',
        },
      },
    },
  },
};

module.exports = swaggerDocument;
EOL
}

# Function to set up initial logger middleware
setup_logger_middleware() {
  cat <<EOL > src/middleware/logger.js
const logger = (req, res, next) => {
  console.log(\`\${new Date().toISOString()} - \${req.method} \${req.originalUrl} - \${req.ip}\`);
  next();
};

module.exports = { logger };
EOL
}

# Function to set up initial error handling middleware
setup_error_handler_middleware() {
  cat <<EOL > src/middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  console.error(\`Error: \${err.message}\`);
  res.status(500).send('Internal Server Error');
};

module.exports = errorHandler;
EOL
}

# Function to set up initial tests
setup_initial_tests() {
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
}

# Function to set up ESLint configuration
setup_eslint_config() {
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
}

# Function to update package.json scripts
update_package_json_scripts() {
  npm set-script start "node src/index.js"
  npm set-script dev "nodemon src/index.js"
  npm set-script test "jest --coverage"
  npm set-script lint "eslint 'src/**/*.js'"
}

# Function to create README.md file
create_readme_file() {
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
}

# Function to create .gitignore file
create_gitignore_file() {
  cat <<EOL > .gitignore
node_modules/
.env
coverage/
EOL
}

# Function to create GitHub Actions CI configuration
create_github_actions_config() {
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
}

# Main function to execute all setup functions
main() {
  command_exists node || {
    echo 'Error: Node.js is required. Please install Node.js (https://nodejs.org/)' >&2
    exit 1
  }

  command_exists npm || {
    echo 'Error: npm is required. Please install npm (https://www.npmjs.com/)' >&2
    exit 1
  }

  create_directory "my-express-app"
  cd "my-express-app" || exit 1

  initialize_npm_project
  install_dependencies
  install_dev_dependencies
  setup_project_structure
  populate_initial_files
  setup_environment_files
  setup_express_app
  setup_initial_routes
  setup_home_controller
  setup_auth_controller
  setup_user_model
  setup_env_validation
  setup_swagger_docs
  setup_logger_middleware
  setup_error_handler_middleware
  setup_initial_tests
  setup_eslint_config
  update_package_json_scripts
  create_readme_file
  create_gitignore_file
  create_github_actions_config

  echo "Express.js starter pack installation complete."
  echo "Run 'npm start' to start the server, 'npm run dev' to start the server with nodemon,"
  echo "'npm test' to run tests, or 'npm run lint' to lint the code."
}

# Execute main function
main
