const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const setupSocket = require('./socket');
// ...existing code...

const app = express();
const server = http.createServer(app);

// 设置Socket.IO服务器
const io = setupSocket(server);

// ...existing code...

// 连接数据库
mongoose.connect('mongodb://localhost:27017/film-browse', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log('MongoDB连接成功'))
    .catch(err => console.error('MongoDB连接失败:', err));

// 启动服务器
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`服务器运行在端口 ${PORT}`);
});
