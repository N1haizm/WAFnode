const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const checkSchema = new Schema({
  ip: {
    type: String,
    required: true,
  },
  maliciousReqCount: {
    type: Number,
    default: 1
  }
});

const CheckSchema = mongoose.model('CheckSchema', checkSchema);
module.exports = CheckSchema