const mongoose = require('mongoose')

const iplistSchema = new mongoose.Schema({
    ip: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    isMalicious: {
        type: Boolean,
        required: true
    },
    payloadType: {
        type: String,
        required: true,
        default: false
    },
    check: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'CheckSchema',
    },
    
}, { timestamps: true });

const Iplist = mongoose.model('iplist', iplistSchema);

module.exports = Iplist;