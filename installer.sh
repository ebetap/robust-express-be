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

# Function to install dependencies with specific versions
install_dependencies() {
  npm install express@^4.17.1 body-parser@^1.19.0 dotenv@^10.0.0 helmet@^4.6.0 cors@^2.8.5 mongoose@^6.2.1 \
    jsonwebtoken@^8.5.1 bcryptjs@^2.4.3 joi@^17.4.0 swagger-ui-express@^4.1.6 express-rate-limit@^5.2.6 \
    csurf@^1.11.0 express-mongo-sanitize@^2.1.0 compression@^1.7.4 morgan@^1.10.0 cookie-parser@^1.4.5 \
    connect-mongo@^4.5.0 multer@^1.4.3 nodemailer@^6.7.2 socket.io@^4.4.1 sequelize@^6.14.0 pg@^8.7.1 mysql2@^2.3.0 \
    sqlite3@^5.0.2 --save
}

# Function to install dev dependencies with specific versions
install_dev_dependencies() {
  npm install --save-dev nodemon@^2.0.15 jest@^27.4.7 supertest@^6.2.0 eslint@^8.3.0 eslint-config-airbnb-base@^16.1.0 \
    eslint-plugin-import@^2.25.2 eslint-plugin-node@^11.1.0 eslint-plugin-jest@^25.1.0 @types/jest@^27.0.3 \
    helmet-csp@^4.4.0 prom-client@^15.3.0 compression@^1.7.4 express-rate-limit@^5.2.6
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
  create_directory "logs"
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

# Function to set up environment files for multiple environments
setup_environment_files() {
  create_file ".env"
  create_file ".env.example"

  if [ ! -s .env.example ]; then
    echo "PORT=3000" >> .env.example
    echo "NODE_ENV=development" >> .env.example
    echo "DB_TYPE=mongodb" >> .env.example  # Default to MongoDB
    echo "MONGO_URI=mongodb://localhost:27017/my-express-app" >> .env.example
    echo "JWT_SECRET=your_jwt_secret" >> .env.example
    echo "CSRF_SECRET=your_csrf_secret" >> .env.example
    echo "MAILER_EMAIL=user@example.com" >> .env.example
    echo "MAILER_PASSWORD=password" >> .env.example
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

# Function to set up initial Sequelize configuration
setup_sequelize() {
  create_directory "src/models"
  create_file "src/config/database.js"
  create_file "src/models/index.js"

  # Sequelize database configuration
  local db_config="src/config/database.js"
  cat <<EOL > "$db_config"
const { Sequelize } = require('sequelize');
const dotenv = require('dotenv');

dotenv.config();

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: process.env.DB_HOST,
  dialect: process.env.DB_DIALECT, // 'mysql' | 'sqlite' | 'postgres' | 'mssql'
});

module.exports = sequelize;
EOL

  # Sequelize model index
  local model_index="src/models/index.js"
  cat <<EOL > "$model_index"
const { Sequelize } = require('sequelize');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

dotenv.config();
const sequelize = require('../config/database');

const db = {};

fs.readdirSync(__dirname)
  .filter(file => file !== 'index.js' && file.endsWith('.js'))
  .forEach(file => {
    const model = require(path.join(__dirname, file))(sequelize, Sequelize.DataTypes);
    db[model.name] = model;
  });

Object.keys(db).forEach(modelName => {
  if (db[modelName].associate) {
    db[modelName].associate(db);
  }
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
EOL
}

# Function to set up initial Mongoose configuration
setup_mongoose() {
  create_directory "src/models"

  # Mongoose model example
  local user_model="src/models/user.js"
  cat <<EOL > "$user_model"
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOL
}

# Function to set up initial Express app configuration with security enhancements
setup_express_app() {
  local index_file="src/index.js"
  cat <<EOL > "$index_file"
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const helmet = require('helmet');
const cors = require('cors');
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
const { authenticateJWT } = require('./middleware/authenticate');
const helmetCsp = require('helmet-csp');

dotenv.config();
validateEnv();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const port = config.PORT || 3000;

// Database connection based on DB_TYPE
if (process.env.DB_TYPE === 'mongodb') {
  const mongoose = require('mongoose');
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
} else if (process.env.DB_TYPE === 'sequelize') {
  const { sequelize } = require('./models'); // Adjust Sequelize import path as necessary
  sequelize.authenticate()
    .then(() => {
      console.log('Connected to the database');
    })
    .catch(err => {
      console.error('Unable to connect to the database:', err);
      process.exit(1);
    });
} else {
  console.error('Unsupported database type. Please set DB_TYPE to "mongodb" or "sequelize" in your .env file.';
  process.exit(1);
}

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
  console.log(\`Server is running on port \${port}\`);
});
EOL
}

# Function to set up initial routes with automated API documentation updates
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
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const config = require('../config/config');

const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate access token
    const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
      expiresIn: '15m',
    });

    // Generate refresh token (stored in cookie)
    const refreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
      expiresIn: '7d',
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      secure: process.env.NODE_ENV === 'production',
    });

    res.json({ accessToken });
  } catch (error) {
    console.error('Error logging in:', error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const register = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error.message);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    return res.status(401).json({ message: 'Refresh token not found' });
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(token, config.JWT_SECRET);

    // Generate new access token
    const accessToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
      expiresIn: '15m',
    });

    res.json({ accessToken });
  } catch (error) {
    console.error('Error refreshing token:', error.message);
    res.status(403).json({ message: 'Invalid refresh token' });
  }
};

module.exports = { login, register, refreshToken };
EOL
}

# Function to set up initial user model for Sequelize or Mongoose
setup_user_model() {
  local db_type="$(grep -oP "(?<=DB_TYPE=).+" .env)"

  if [[ "$db_type" == "sequelize" ]]; then
    local user_model="src/models/user.js"
    cat <<EOL > "$user_model"
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const User = sequelize.define('User', {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

module.exports = User;
EOL
  elif [[ "$db_type" == "mongodb" ]]; then
    local user_model="src/models/user.js"
    cat <<EOL > "$user_model"
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

module.exports = User;
EOL
  else
    echo "Unsupported database type '$db_type'."
    exit 1
  fi
}

# Function to set up initial middleware for authentication
setup_authentication_middleware() {
  local authenticate_middleware="src/middleware/authenticate.js"
  cat <<EOL > "$authenticate_middleware"
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
EOL
}

# Function to set up initial error handler middleware
setup_error_handler_middleware() {
  local error_handler="src/middleware/errorHandler.js"
  cat <<EOL > "$error_handler"
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Internal server error' });
};

module.exports = errorHandler;
EOL
}

# Function to set up initial Jest test file
setup_initial_tests() {
  local tests_file="src/tests/index.test.js"
  cat <<EOL > "$tests_file"
const request = require('supertest');
const app = require('../index');

describe('GET /', () => {
  it('should return 200 OK', async () => {
    const response = await request(app).get('/');
    expect(response.status).toBe(200);
    expect(response.text).toBe('Hello World!');
  });
});
EOL
}

# Main function to call all setup functions based on chosen database type
setup_express_app_setup_script() {
  initialize_npm_project
  install_dependencies
  install_dev_dependencies
  setup_project_structure
  populate_initial_files
  setup_environment_files

  local db_type="$(grep -oP "(?<=DB_TYPE=).+" .env)"

  if [[ "$db_type" == "sequelize" ]]; then
    setup_sequelize
  elif [[ "$db_type" == "mongodb" ]]; then
    setup_mongoose
    echo "MongoDB selected. Setting up Mongoose..."
  else
    echo "Unsupported database type '$db_type'. Please set DB_TYPE to 'sequelize' or 'mongodb'."
    exit 1
  fi

  setup_express_app
  setup_initial_routes
  setup_home_controller
  setup_auth_controller
  setup_user_model
  setup_authentication_middleware
  setup_error_handler_middleware
  setup_initial_tests

  echo "Setup completed successfully!"
}

# Main execution
setup_express_app_setup_script
