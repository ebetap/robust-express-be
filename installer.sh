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
npm install express body-parser dotenv helmet cors

# Install development dependencies
npm install --save-dev nodemon jest supertest eslint

# Create directories and initial files
mkdir -p src/routes src/config src/middleware src/controllers src/tests
touch src/index.js src/routes/index.js src/config/config.js src/middleware/logger.js src/middleware/errorHandler.js src/controllers/homeController.js src/tests/index.test.js

# Create a .env file (template)
touch .env .env.example
echo "PORT=3000" >> .env.example
echo "NODE_ENV=development" >> .env.example
cp .env.example .env

# Add basic Express server setup to src/index.js
cat <<EOL > src/index.js
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const morgan = require('morgan');
const helmet = require('helmet');
const cors = require('cors');
const routes = require('./routes');
const { logger } = require('./middleware/logger');
const errorHandler = require('./middleware/errorHandler');
const config = require('./config/config');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Security middlewares
app.use(helmet());
app.use(cors());

// Middleware
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(logger);

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

const router = express.Router();

router.get('/', homeController.getHome);

module.exports = router;
EOL

# Add basic controller setup to src/controllers/homeController.js
cat <<EOL > src/controllers/homeController.js
const getHome = (req, res) => {
  res.send('Hello World!');
};

module.exports = { getHome };
EOL

# Add basic configuration to src/config/config.js
cat <<EOL > src/config/config.js
const config = {
  development: {
    port: process.env.PORT || 3000,
    envName: 'development',
  },
  production: {
    port: process.env.PORT || 3000,
    envName: 'production',
  },
};

const env = process.env.NODE_ENV || 'development';

module.exports = config[env];
EOL

# Add logger middleware to src/middleware/logger.js
cat <<EOL > src/middleware/logger.js
const logger = (req, res, next) => {
  console.log(\`\${req.method} \${req.url}\`);
  next();
};

module.exports = { logger };
EOL

# Add error handling middleware to src/middleware/errorHandler.js
cat <<EOL > src/middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
};

module.exports = errorHandler;
EOL

# Add basic test setup to src/tests/index.test.js
cat <<EOL > src/tests/index.test.js
const request = require('supertest');
const app = require('../index');

describe('GET /', () => {
  it('should return Hello World!', async () => {
    const res = await request(app).get('/');
    expect(res.statusCode).toEqual(200);
    expect(res.text).toBe('Hello World!');
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
