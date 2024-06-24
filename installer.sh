#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Function to create directory if not exists
create_directory() {
  local dir="$1"
  if [ -d "$dir" ]; then
    echo "Directory '$dir' already exists. Skipping creation."
  else
    mkdir -p "$dir"
    echo "Created directory: $dir"
  fi
}

# Function to create file if not exists
create_file() {
  local file="$1"
  if [ ! -f "$file" ]; then
    touch "$file"
    echo "Created file: $file"
  else
    echo "File '$file' already exists. Skipping creation."
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
  local index_file="src/index.js"
  cat <<EOL > "$index_file"
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
const { authenticateJWT } = require('./middleware/authenticate');

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
  local routes_file="src/routes/index.js"
  cat <<EOL > "$routes_file"
const express = require('express');
const homeController = require('../controllers/homeController');
const authController = require('../controllers/authController');
const { authenticateJWT } = require('../middleware/authenticate');

const router = express.Router();

router.get('/', homeController.getHome);
router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/refresh-token', authController.refreshToken); // New endpoint for token refresh

module.exports = router;
EOL
}

# Function to set up initial home controller
setup_home_controller() {
  local home_controller="src/controllers/homeController.js"
  cat <<EOL > "$home_controller"
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
EOL
}

# Function to set up initial auth controller with JWT authentication and refresh tokens
setup_auth_controller() {
  local auth_controller="src/controllers/authController.js"
  cat <<EOL > "$auth_controller"
const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '15m' });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
};

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
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    res.status(200).json({ accessToken, refreshToken });
  } catch (err) {
    console.error('Error logging in:', err.message);
    res.status(500).send('Error logging in');
  }
};

const refreshToken = async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).send('Refresh token is required');
  }
  try {
    jwt.verify(refreshToken, JWT_SECRET);
    const decoded = jwt.decode(refreshToken);
    const accessToken = generateAccessToken(decoded.id);
    res.status(200).json({ accessToken });
  } catch (err) {
    console.error('Error refreshing token:', err.message);
    res.status(403).send('Invalid refresh token');
  }
};

module.exports = { register, login, refreshToken };
EOL
}

# Function to set up initial user model
setup_user_model() {
  local user_model="src/models/user.js"
  cat <<EOL > "$user_model"
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' } // Role-based access control
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOL
}

# Function to set up initial environment validation (continued)
setup_env_validation() {
  local env_validation="src/config/validateEnv.js"
  cat <<EOL > "$env_validation"
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
  local swagger_docs="src/docs/swagger.js"
  cat <<EOL > "$swagger_docs"
const swaggerDocument = {
  openapi: '3.0.0',
  info: {
    title: 'Express API Documentation',
    version: '1.0.0',
    description: 'API Documentation for Express App',
  },
  servers: [
    {
      url: 'http://localhost:3000',
      description: 'Development Server',
    },
  ],
  paths: {
    '/': {
      get: {
        summary: 'Home endpoint',
        responses: {
          '200': {
            description: 'Successful response',
          },
        },
      },
    },
    '/login': {
      post: {
        summary: 'Login endpoint',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: {
                    type: 'string',
                  },
                  password: {
                    type: 'string',
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Successful login',
          },
          '401': {
            description: 'Invalid credentials',
          },
        },
      },
    },
    '/register': {
      post: {
        summary: 'Register endpoint',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: {
                    type: 'string',
                  },
                  password: {
                    type: 'string',
                  },
                },
              },
            },
          },
        },
        responses: {
          '201': {
            description: 'User registered successfully',
          },
          '500': {
            description: 'Error registering user',
          },
        },
      },
    },
    '/refresh-token': {
      post: {
        summary: 'Refresh token endpoint',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  refreshToken: {
                    type: 'string',
                  },
                },
              },
            },
          },
        },
        responses: {
          '200': {
            description: 'Token refreshed successfully',
          },
          '401': {
            description: 'Refresh token is required',
          },
          '403': {
            description: 'Invalid refresh token',
          },
        },
      },
    },
  },
};

module.exports = swaggerDocument;
EOL
}

# Function to set up JWT authentication middleware
setup_jwt_middleware() {
  local jwt_middleware="src/middleware/authenticate.js"
  cat <<EOL > "$jwt_middleware"
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = process.env;

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }

      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

module.exports = { authenticateJWT };
EOL
}

# Function to set up initial error handling middleware
setup_error_handler() {
  local error_handler="src/middleware/errorHandler.js"
  cat <<EOL > "$error_handler"
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
};

module.exports = errorHandler;
EOL
}

# Function to set up logging middleware
setup_logger() {
  local logger="src/middleware/logger.js"
  cat <<EOL > "$logger"
const logger = (req, res, next) => {
  console.log(\`\${req.method} \${req.url}\`);
  next();
};

module.exports = { logger };
EOL
}

# Function to seed the database with initial data
seed_database() {
  local seed_file="src/config/seed.js"
  cat <<EOL > "$seed_file"
const mongoose = require('mongoose');
const User = require('../models/user');

const seedData = async () => {
  await mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  const admin = new User({
    username: 'admin',
    password: await bcrypt.hash('adminpassword', 10),
    role: 'admin',
  });

  await admin.save();
  console.log('Admin user created');

  mongoose.connection.close();
};

seedData().catch(err => console.error(err));
EOL
}

# Function to set up Dockerfile
setup_dockerfile() {
  cat <<EOL > Dockerfile
FROM node:14

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3000
CMD ["node", "src/index.js"]
EOL
}

# Function to set up Docker Compose
setup_docker_compose() {
  cat <<EOL > docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    env_file:
      - .env
    depends_on:
      - mongo
  mongo:
    image: mongo:4.2
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME: root
      MONGO_INITDB_ROOT_PASSWORD: example
EOL
}

# Function to set up CI/CD with GitHub Actions
setup_github_actions() {
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
        node-version: [14, 16]

    steps:
    - uses: actions/checkout@v2
    - name: Use Node.js \${{ matrix.node-version }}
      uses: actions/setup-node@v2
      with:
        node-version: \${{ matrix.node-version }}
    - run: npm install
    - run: npm run lint
    - run: npm test
    - run: npm run build --if-present
EOL
}

# Function to complete the setup
complete_setup() {
  echo "Setup completed successfully!"
}

# Main function to execute setup steps
main() {
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
  setup_jwt_middleware
  setup_error_handler
  setup_logger
  seed_database
  setup_dockerfile
  setup_docker_compose
  setup_github_actions
  complete_setup
}

# Execute the main function
main
