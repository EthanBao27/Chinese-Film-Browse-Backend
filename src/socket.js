const socketIO = require('socket.io');
const Message = require('./models/message'); // 假设有消息模型

// 存储每个电影的在线用户
const movieRooms = {};

function setupSocket(server) {
    const io = socketIO(server, {
        cors: {
            origin: "*",
            methods: ["GET", "POST"]
        }
    });

    io.on('connection', (socket) => {
        const username = socket.handshake.query.username || '匿名用户';
        const movieId = socket.handshake.query.movieId;

        // 加入特定电影的聊天室
        socket.join(`movie-${movieId}`);

        // 初始化电影房间数据
        if (!movieRooms[movieId]) {
            movieRooms[movieId] = new Set();
        }

        // 添加用户到当前电影的在线列表
        movieRooms[movieId].add(username);

        // 广播当前电影的在线人数
        io.to(`movie-${movieId}`).emit('show count', {
            count: movieRooms[movieId].size
        });

        // 发送用户加入通知给当前电影聊天室
        socket.to(`movie-${movieId}`).emit('login message', {
            msg: `${username} 加入了聊天室`,
            created_at: new Date().toISOString()
        });

        // 加载当前电影的历史消息
        Message.find({ movieId: movieId })
            .sort({ created_at: -1 })
            .limit(50)
            .then(messages => {
                socket.emit('load previous messages', messages.reverse());
            })
            .catch(err => console.error('加载历史消息失败:', err));

        // 处理聊天消息
        socket.on('chat message', (messageData) => {
            // 确保消息与当前电影匹配
            if (messageData.movieId === movieId) {
                // 保存消息到数据库
                const message = new Message({
                    msg: messageData.msg,
                    username: username,
                    movieId: movieId,
                    color: messageData.color,
                    created_at: messageData.created_at
                });

                message.save()
                    .then(() => {
                        // 只向当前电影的聊天室广播消息
                        io.to(`movie-${movieId}`).emit('chat message', {
                            ...messageData,
                            username: username
                        });
                    })
                    .catch(err => console.error('保存消息失败:', err));
            }
        });

        // 断开连接处理
        socket.on('disconnect', () => {
            if (movieRooms[movieId]) {
                movieRooms[movieId].delete(username);

                // 广播更新后的在线人数
                io.to(`movie-${movieId}`).emit('show count', {
                    count: movieRooms[movieId].size
                });

                // 广播用户离开消息
                socket.to(`movie-${movieId}`).emit('login message', {
                    msg: `${username} 离开了聊天室`,
                    created_at: new Date().toISOString()
                });

                // 如果房间为空，清理内存
                if (movieRooms[movieId].size === 0) {
                    delete movieRooms[movieId];
                }
            }
        });
    });

    return io;
}

module.exports = setupSocket;
