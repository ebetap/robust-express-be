
#!/bin/bash

# Check if Node.js is installed
if ! [ -x "$(command -v node)" ]; then
  echo 'Error: Node.js is not installed. Please install Node.js (https://nodejs.org/)' >&2
  exit 1
fi

# Create a new directory for the project
mkdir my-express-app
cd my-express-app

# Initialize npm project
npm init -y

# Install Express.js and other dependencies
npm install express body-parser dotenv

# Create directories and initial files
mkdir src
touch src/index.js

# Create a .env file (template)
touch .env
echo "PORT=3000" >> .env

# Completion message
echo "Express.js starter pack installation complete. Run 'npm start' to start the server."
