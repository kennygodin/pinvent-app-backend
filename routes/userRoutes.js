const express = require('express');
const {
  registerUser,
  loginUser,
  logoutUser,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
} = require('../controllers/userController');
const protect = require('../middleware/authMiddleware');

const router = express.Router();

// creating user registration route

router.post('/register', registerUser);

// creating a user login route
router.post('/login', loginUser);

// creating a user logout route
router.get('/logout', logoutUser);

// get user profile route
router.get('/getuser', protect, getUser);

// logged in status route
router.get('/loggedin', loginStatus);

// update the current user profile excluding password route
router.patch('/updateuser', protect, updateUser);

// update routes for the user password
router.patch('/changepassword', protect, changePassword);

// route for the forgot password
router.post('/forgotpassword', forgotPassword);

// routes for the reset password
router.put('/resetpassword/:resetToken', resetPassword);

module.exports = router;
