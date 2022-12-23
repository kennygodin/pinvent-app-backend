const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const tokenSchema = new Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'user',
  },
  token: {
    type: String,
    required: true,
  },
  createdAt: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: String,
    required: true,
  },
});

const Token = mongoose.model('token', tokenSchema);

module.exports = Token;
