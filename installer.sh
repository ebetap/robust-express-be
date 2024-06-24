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
npm install express body-parser dotenv morgan

# Install development dependencies
npm install --save-dev nodemon jest supertest

# Create directories and initial files
mkdir -p src/routes src/config src/middleware src/tests
touch src/index.js src/routes/index.js src/config/config.js src/middleware/logger.js src/middleware/errorHandler.js src/tests/index.test.js

# Create a .env file (template)
touch .env
echo "PORT=3000" >> .env
echo "NODE_ENV=development" >> .env

# Add basic Express server setup to src/index.js
cat <<EOL > src/index.js
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const morgan = require('morgan');
const routes = require('./routes');
const { logger } = require('./middleware/logger');
const errorHandler = require('./middleware/errorHandler');
const config = require('./config/config');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

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
const router = express.Router();

router.get('/', (req, res) => {
  res.send('Hello World!');
});

module.exports = router;
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

# Add start, dev, and test scripts to package.json
npm set-script start "node src/index.js"
npm set-script dev "nodemon src/index.js"
npm set-script test "jest --coverage"

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

## Built With

- [Express](https://expressjs.com/) - The web framework used
- [Nodemon](https://nodemon.io/) - Used for development to automatically restart the server
- [Jest](https://jestjs.io/) - Testing framework
- [Supertest](https://github.com/visionmedia/supertest) - HTTP assertions for testing

## Authors

- **Your Name** - *Initial work* - [YourGitHub](https://github.com/yourusername)
EOL

# Create a .gitignore file
cat <<EOL > .gitignore
node_modules/
.env
coverage/
EOL

# Completion message
echo "Express.js starter pack installation complete. Run 'npm start' to start the server, 'npm run dev' to start the server with Nodemon, or 'npm test' to run tests."
