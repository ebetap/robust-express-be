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
  cat <<EOL > src/routes/index.js
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
  cat <<EOL > src/controllers/homeController.js
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
EOL
}

# Function to set up initial auth controller with JWT authentication and refresh tokens
setup_auth_controller() {
  cat <<EOL > src/controllers/authController.js
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
  cat <<EOL > src/models/user.js
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
};

module.exports = swaggerDocument;
EOL
}

# Function to set up JWT authentication middleware
setup_jwt_middleware() {
  cat <<EOL > src/middleware/authenticate.js
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
  cat <<EOL > src/middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
};

module.exports = errorHandler;
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
  complete_setup
}

# Execute the main function
main
