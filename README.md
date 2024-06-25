# Node.js Express Application Setup Script Documentation

## Overview

This setup script automates the process of initializing, configuring, and structuring a Node.js Express application. It supports both MongoDB and Sequelize (SQL) databases, providing flexibility based on your project's database requirements. The script also installs necessary dependencies, sets up project structure, initializes configuration files, and creates initial files like controllers, models, routes, and middleware.

## Prerequisites

Before running the script, ensure the following prerequisites are met:

- **Node.js and npm**: Ensure Node.js and npm (Node Package Manager) are installed on your system.
- **MongoDB or SQL Database**: Depending on your choice (MongoDB or Sequelize), ensure the corresponding database server is installed and running.
- **Environment Setup**: Prepare a `.env` file with necessary environment variables specific to your database configuration (see `.env.example` section).

## Script Functions

The script performs the following functions:

1. **Check Command Existence**: Ensures required commands (`npm`, `node`) are available.
   
2. **Create Directory**: Creates directories if they do not exist, necessary for project structure.

3. **Create File**: Creates files if they do not exist, such as main application files, configuration files, controllers, models, tests, etc.

4. **Initialize npm Project**: Initializes an npm project (`npm init -y`) if `package.json` does not exist.

5. **Install Dependencies**: Installs necessary npm packages for Express, database connectors (mongoose or sequelize), middleware, and testing libraries.

6. **Install Development Dependencies**: Installs development dependencies like `nodemon`, `jest`, and `supertest` for automated testing and development purposes.

7. **Setup Project Structure**: Creates a predefined directory structure (`src`, `src/routes`, `src/config`, `src/middleware`, `src/controllers`, `src/tests`, `src/models`, `src/docs`, `logs`) to organize application code and resources.

8. **Populate Initial Files**: Creates initial files (`index.js`, `routes/index.js`, `config/config.js`, `middleware/logger.js`, `middleware/errorHandler.js`, `controllers/homeController.js`, `controllers/authController.js`, `tests/index.test.js`, `models/user.js`, `config/validateEnv.js`, `docs/swagger.js`) with basic boilerplate code to get started.

9. **Setup Environment Files**: Creates `.env` and `.env.example` files if they do not exist, populates them with default configurations for MongoDB or Sequelize setups.

10. **Setup Sequelize**: Sets up Sequelize configuration files (`src/config/database.js`, `src/models/index.js`) and model (`src/models/user.js`) if `DB_TYPE` is set to `sequelize`.

11. **Setup Mongoose**: Sets up Mongoose model (`src/models/user.js`) if `DB_TYPE` is set to `mongodb`.

12. **Setup Express Application**: Configures an initial Express application (`src/index.js`) with security middlewares, CORS, rate limiting, logging, compression, CSRF protection, and error handling.

13. **Setup Initial Routes**: Creates initial routes (`src/routes/index.js`) and links controllers (`homeController`, `authController`) to handle HTTP requests.

14. **Setup Home Controller**: Sets up a basic controller (`homeController.js`) with a sample route handler (`getHome`) returning a simple message.

15. **Setup Auth Controller**: Implements authentication logic (`authController.js`) using JWT for login, registration, and token refresh.

16. **Setup User Model**: Creates a user model (`user.js`) using Sequelize or Mongoose based on `DB_TYPE`.

17. **Setup Authentication Middleware**: Implements JWT authentication middleware (`authenticate.js`) to protect routes requiring authentication.

18. **Setup Error Handler Middleware**: Sets up a generic error handler middleware (`errorHandler.js`) to handle server errors and exceptions.

19. **Setup Initial Tests**: Initializes a basic test (`index.test.js`) using Jest and Supertest to test a sample route.

20. **Main Execution**: Combines all setup functions and executes based on `DB_TYPE` specified in the `.env` file.

## `.env` Configuration

Ensure your `.env` file is configured appropriately based on your chosen database (`mongodb` or `sequelize`). Here's an example configuration for both setups:

### Example `.env` File for MongoDB

```plaintext
PORT=3000
NODE_ENV=development
DB_TYPE=mongodb
MONGO_URI=mongodb://localhost:27017/my-express-app
JWT_SECRET=your_jwt_secret
CSRF_SECRET=your_csrf_secret
MAILER_EMAIL=user@example.com
MAILER_PASSWORD=password
```

### Example `.env` File for Sequelize (MySQL) Setup

```plaintext
PORT=3000
NODE_ENV=development
DB_TYPE=sequelize
DB_NAME=my_database
DB_USER=my_user
DB_PASSWORD=my_password
DB_HOST=localhost
DB_DIALECT=mysql
JWT_SECRET=your_jwt_secret
CSRF_SECRET=your_csrf_secret
MAILER_EMAIL=user@example.com
MAILER_PASSWORD=password
```

## Running the Script

To run the setup script:

1. Save the script (`setup_script.sh`) in your project directory.
2. Open a terminal and navigate to the project directory.
3. Make the script executable if necessary: `chmod +x setup_script.sh`.
4. Run the script: `./setup_script.sh`.

Follow the prompts and instructions provided by the script to complete the setup process. Ensure you review and adjust configurations as per your specific project requirements.

## Notes

- **Security**: Keep `.env` files secure and do not expose them publicly.
- **Customization**: Modify the script as needed to fit additional project requirements or preferences.
- **Documentation**: Keep this document updated as the project evolves to reflect any changes or additional configurations.
