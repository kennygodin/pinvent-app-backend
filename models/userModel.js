const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const Schema = mongoose.Schema;

const userSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, 'Please add a name'],
    },
    email: {
      type: String,
      required: [true, 'Please add an email'],
      unique: true,
      trim: true,
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'Please enter a valid email',
      ],
    },
    password: {
      type: String,
      required: [true, 'Please add a password'],
      minlength: [6, 'Password must be up to 6 characters'],
      // maxlength: [23, 'Password must not be more than 23 characters'],
    },
    photo: {
      type: String,
      required: [true, 'Please enter a photo'],
      default: 'https://i.ibb.co/4pDNDk1/avatar.png',
    },
    phone: {
      type: String,
      default: +234,
    },
    bio: {
      type: String,
      default: 'bio',
      maxlength: [250, 'Bio must not be more than 250 characters'],
    },
  },
  { timestamps: true }
);

// encrypt the password before saving to the db.
userSchema.pre('save', async function (next) {
  // check if the password isnt modified
  if (!this.isModified('password')) {
    return next();
  }

  // hash password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);

  this.password = hashedPassword;
  next();
});
const User = mongoose.model('user', userSchema);

module.exports = User;
