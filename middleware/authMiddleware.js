const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');

const protect = asyncHandler(async (req, res, next) => {
  try {
    // Check to see if we have the cookie stored in the frontend.

    const token = req.cookies.token;

    if (!token) {
      res.status(401);
      throw new Error('Not authorized, please login');
    }

    // if it came with a token, verify
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // get user id from token
    let user = await User.findById(verified.id).select('-password');

    if (!user) {
      res.status(401);
      throw new Error('User not found');
    }
    // if user was found
    req.user = user;
    next();
  } catch (error) {
    res.status(401);
    throw new Error('Not authorized, please login');
  }
});

module.exports = protect;
