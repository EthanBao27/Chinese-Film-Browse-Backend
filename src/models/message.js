const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    msg: {
        type: String,
        required: true
    },
    username: {
        type: String,
        default: '匿名用户'
    },
    movieId: {
        type: String,
        required: true,
        index: true // 添加索引以提高查询性能
    },
    color: {
        type: String,
        default: '#000000'
    },
    created_at: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Message', messageSchema);
