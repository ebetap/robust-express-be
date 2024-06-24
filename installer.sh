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
npm install express body-parser dotenv

# Install Nodemon for development
npm install --save-dev nodemon

# Create directories and initial files
mkdir -p src/routes
touch src/index.js src/routes/index.js

# Create a .env file (template)
touch .env
echo "PORT=3000" >> .env

# Add basic Express server setup to src/index.js
cat <<EOL > src/index.js
const express = require('express');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const routes = require('./routes');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use('/', routes);

app.listen(port, () => {
  console.log(\`Server is running on port \${port}\`);
});
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

# Add start and dev scripts to package.json
npm set-script start "node src/index.js"
npm set-script dev "nodemon src/index.js"

# Create a README.md file
touch README.md
echo "# My Express App" >> README.md
echo "This is a simple Express.js project." >> README.md

# Create a .gitignore file
touch .gitignore
echo "node_modules/" >> .gitignore
echo ".env" >> .gitignore

# Completion message
echo "Express.js starter pack installation complete. Run 'npm start' to start the server or 'npm run dev' to start the server with Nodemon."
