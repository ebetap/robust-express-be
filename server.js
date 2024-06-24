// server.js

const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const mongoURI = process.env.MONGO_URI;

// Middleware
app.use(express.json()); // Parse JSON bodies
// Add more middleware as needed

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');

  // Auto-generate APIs
  const User = require('./models/User'); // Example model
  const generateAPIs = require('./generateApis');
  app.use('/api/users', generateAPIs(User));

  app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
  });
});
