const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Token = require('../models/tokenModel');
const sendEmail = require('../utils/sendEmail');

// generating a token with the user id
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '1d' });
};

// creating user registration route/ signing up  user
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //   validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error('Please fill all required fields');
  }
  if (password.length < 6) {
    res.status(400);
    throw new Error('Password must be up to 6 characters');
  }

  // check if user email already exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400);
    throw new Error('Email has already been registered');
  }

  // create new user
  const user = await User.create({
    name,
    email,
    password,
  });

  // generate token before creating the user
  const token = generateToken(user._id);

  // send HTTP-only cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: 'none',
    secure: true,
  });
  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid user data');
  }
});

// log in user to the app.
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // validate request
  if (!email || !password) {
    res.status(400);
    throw new Error('Please fill all fields');
  }

  // check if the user exists in the DB
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error('User not found. Please signup');
  }

  // user exists, now check if the password is correct
  const passwordIsCorrect = await bcrypt.compare(password, user.password);

  // generate token before creating the user
  const token = generateToken(user._id);

  // send HTTP-only cookie
  res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 day
    sameSite: 'none',
    secure: true,
  });
  if (user && passwordIsCorrect) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid email or password');
  }
});

// Logout the user
const logoutUser = asyncHandler(async (req, res) => {
  res.cookie('token', '', {
    path: '/',
    httpOnly: true,
    expires: new Date(0),
    sameSite: 'none',
    secure: true,
  });

  res.status(200).json({ message: 'Successfully Logged Out' });
});

// get user data or profile
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
    });
  } else {
    res.status(400);
    throw new Error('User Not Found');
  }
});

// get logged in status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    // boolean, returns true or false
    return res.json(false);
  }
  // If there's a token, then verify
  const verified = jwt.verify(token, process.env.JWT_SECRET);

  // if verified ie user is logged in
  if (verified) {
    return res.json(true);
  } else {
    return res.json(false);
  }
});

// Updating the user data excluding password.
const updateUser = asyncHandler(async (req, res) => {
  // get the user data; this is a protected route, we have the req.user
  // to get the user id
  const user = await User.findById(req.user._id);

  // if we get user, he can choose to update ever property, so we distructure
  // all properties of the user
  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    user.email = email; // you don't want user to change email
    user.name = req.body.name || name;
    user.photo = req.body.photo || photo;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;

    // save the user
    const updatedUser = await user.save();

    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      photo: updatedUser.photo,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
    });
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

// change user password
const changePassword = asyncHandler(async (req, res) => {
  // get the user data; this is a protected route, we have the req.user
  // to get the user id
  const user = await User.findById(req.user._id);

  if (!user) {
    req.status(400);
    throw new Error('User not found, please signup');
  }

  // get the old password and the new password from the frontend
  const { oldPassword, password } = req.body;

  // Validation
  if (!oldPassword || !password) {
    res.status(400);
    throw new Error('Please add old and new password');
  }

  // check if oldPassoword match with password in the database
  const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

  // save new password
  if (user && passwordIsCorrect) {
    user.password = password;

    // then save
    await user.save();

    res.status(200).send('Password Change Successful');
  } else {
    res.status(400);
    throw new Error('Old password is incorrect');
  }
});

// forgot password
const forgotPassword = asyncHandler(async (req, res) => {
  // get the email from the frontend.
  const { email } = req.body;

  // check if the email is in our DB.
  const user = await User.findOne({ email });

  if (!user) {
    res.status(400);
    throw new Error('User does not exist');
  }

  // delete token if it exists in the DB
  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // create reset token.
  let resetToken = crypto.randomBytes(32).toString('hex') + user._id;
  console.log(resetToken);
  // hash token before saving to the DB
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // save token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), // expires after 30mins
  }).save();

  // construct reset url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  // Reset email
  const message = `
    <h2>Hello ${user.name}</h2>
    <p>Please use the url below</p>
    <p>This reset link is valid for 30 minutes</p>

    <a  href=${resetUrl} clicktracking=off>${resetUrl}</a>

    <p>Regards...</p>
    <p>Pinvent Team</p>
  `;

  const subject = 'Password Reset Request';
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, sent_from);

    res.status(200).json({ success: true, message: 'Reset email sent' });
  } catch (error) {
    res.status(500);
    throw new Error('Email not sent please try again');
  }
});

const resetPassword = asyncHandler(async (req, res) => {
  // We need two piece of data, the password and params
  const { password } = req.body;
  const { resetToken } = req.params;

  // hash token, then compare with the token in the DB
  const hashedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  // Find the token in the DB
  const userToken = await Token.findOne({
    token: hashedToken,
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error('Invalid or expired token');
  }

  // Find user
  const user = await User.findOne({ _id: userToken.userId });
  // then set the password
  user.password = password;

  await user.save();

  res.status(200).json({ message: 'Password Reset Successfull, Please Login' });
});

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
};
