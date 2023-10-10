const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());

const users = [];
let userIdCounter = 1;

const secretKey = 'your-secret-key';

const registrationValidationRules = [
  body('fullName').notEmpty().withMessage('Full name must not be empty'),
  body('email')
    .notEmpty()
    .withMessage('Email must not be empty')
    .isEmail()
    .withMessage('Invalid email format')
    .custom((value) => {
     
      const existingUser = users.find((user) => user.email === value);
      if (existingUser) {
        throw new Error('Email is already registered');
      }
      return true;
    }),
  body('password')
    .notEmpty()
    .withMessage('Password must not be empty')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/[\d\W]/)
    .withMessage('Password must contain at least 1 symbol'),
  body('bio').optional(),
  body('dob')
    .optional()
    .isDate()
    .withMessage('Date of birth must be a valid date (YYYY-MM-DD)'),
];

app.post('/auth/register', registrationValidationRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ message: 'Validation Error', detail: errors.array() });
  }

  const { fullName, email, password, bio, dob } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = {
    id: userIdCounter++,
    fullName,
    email,
    password: hashedPassword,
    bio,
    dob,
  };

  users.push(user);

  res.status(201).json({ message: 'Success' });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(401).json({ message: 'Login Failed' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ message: 'Login Failed' });
  }

  const token = jwt.sign({ id: user.id, email: user.email }, secretKey);

  res.status(200).json({ message: 'Success', data: { token } });
});

app.get('/users', (req, res) => {
  if (users.length === 0) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.status(200).json({ message: 'Success', data: users });
});

app.get('/users/:userId', (req, res) => {
  const { userId } = req.params;
  const user = users.find((user) => user.id === parseInt(userId));

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  res.status(200).json({ message: 'Success', data: user });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
