const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  // Import Pino logger
const { body, validationResult } = require('express-validator');
dotenv.config();

const logger = pino();  // Create a Pino logger instance

//Create JWT secret
dotenv.config();
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
      //Connect to `giftsdb` in MongoDB through `connectToDatabase` in `db.js`.
      const db = await connectToDatabase();

      //Access the `users` collection
      const collection = db.collection("users");

      //Check for existing email in DB
      const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }

        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        const email=req.body.email;

        //Save user details
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        //Create JWT
        const authtoken = jwt.sign(payload, JWT_SECRET);
        logger.info('User registered successfully');
        res.json({ authtoken,email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

    //Login Endpoint
router.post('/login', async (req, res) => {
    console.log("\n\n Inside login")

    try {
        const db = await connectToDatabase();
        const collection = db.collection("users");
        const theUser = await collection.findOne({ email: req.body.email });

        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
            if(!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            let payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };

            const userName = theUser.firstName;
            const userEmail = theUser.email;

            const authtoken = jwt.sign(payload, JWT_SECRET);
            logger.info('User logged in successfully');
            return res.status(200).json({ authtoken, userName, userEmail });
        } else {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }
    } catch (e) {
        logger.error(e);
        return res.status(500).json({ error: 'Internal server error', details: e.message });
      }
});

// {Insert it along with other imports} Task 1: Use the `body`,`validationResult` from `express-validator` for input validation

router.put('/update', async (req, res) => {
const errors = validationResult(req);

if (!errors.isEmpty()) {
    logger.error('Validation errors in update request', errors.array());
    res.status(400).json({errors: errors.array()});
}
    // Task 2: Validate the input using `validationResult` and return approiate message if there is an error.
try {
    const db = await connectToDatabase();
    const collection = db.collection("users");
    const email = req.headers.email;
    if (!email) {
        res.status(404).json({error: 'Email not found in the request headers'});
    }

    let existingUser = await collection.findOne({email});
    // Task 3: Check if `email` is present in the header and throw an appropriate error message if not present.
    // Task 4: Connect to MongoDB
    // Task 5: find user credentials in database

    existingUser.updatedAt = new Date();

    const updateUser = await collection.findOneAndUpdate(
        {email},
        {$set: existingUser},
        { returnDocument: 'after' }
    );

    const payload = {
        user: {
            id: updateUser._id.toString(),
        },
    };

    const authtoken = jwt.sign(payload, JWT_SECRET);
    logger.info('User updated successfully');
    // Task 6: update user credentials in database
    // Task 7: create JWT authentication using secret key from .env file
    res.json({authtoken});
} catch (e) {
    logger.error(e);
     return res.status(500).send('Internal server error');
}
});

module.exports = router;