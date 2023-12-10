const mongoose = require('mongoose')

const Schema = mongoose.Schema

const blockedipsSchema = new Schema({
    ip: {
        type: String,
        required: true
    },
    blockType: {
        type: String,
        required: true
    }
})

const Blockedips = mongoose.model('Blockedips', blockedipsSchema)
module.exports = Blockedips