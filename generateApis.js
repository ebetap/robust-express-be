// generateApis.js

const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

const generateAPIs = (model) => {
  // Create
  router.post('/', async (req, res) => {
    try {
      const instance = new model(req.body);
      await instance.save();
      res.status(201).send(instance);
    } catch (err) {
      res.status(400).send(err);
    }
  });

  // Read all
  router.get('/', async (req, res) => {
    try {
      const instances = await model.find();
      res.send(instances);
    } catch (err) {
      res.status(500).send(err);
    }
  });

  // Read by ID
  router.get('/:id', async (req, res) => {
    try {
      const instance = await model.findById(req.params.id);
      if (!instance) {
        return res.status(404).send({ error: 'Instance not found' });
      }
      res.send(instance);
    } catch (err) {
      res.status(500).send(err);
    }
  });

  // Update
  router.put('/:id', async (req, res) => {
    try {
      const instance = await model.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true,
      });
      if (!instance) {
        return res.status(404).send({ error: 'Instance not found' });
      }
      res.send(instance);
    } catch (err) {
      res.status(400).send(err);
    }
  });

  // Delete
  router.delete('/:id', async (req, res) => {
    try {
      const instance = await model.findByIdAndDelete(req.params.id);
      if (!instance) {
        return res.status(404).send({ error: 'Instance not found' });
      }
      res.send(instance);
    } catch (err) {
      res.status(500).send(err);
    }
  });

  return router;
};

module.exports = generateAPIs;
