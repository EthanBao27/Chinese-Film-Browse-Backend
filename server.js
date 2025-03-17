const app = require("express")()
const mysql = require('mysql2')
const bcrypt = require('bcryptjs')
const bodyParser = require('body-parser')
const cors = require('cors')
const session = require('express-session');
const server = require('http').createServer(app)
const { Server } = require('socket.io')
const io = new Server(server, {
    cors: {
        origin: ['http://8.153.74.243', 'http://localhost'],  // 允许本地和服务器地址
        methods: ['GET', 'POST'],  // 允许的HTTP方法
        credentials: true  // 允许凭证（如Cookies）
    },
    // 优化Socket.IO配置
    pingTimeout: 60000, // 增加ping超时时间为60秒
    pingInterval: 25000, // 每25秒ping一次客户端
    connectTimeout: 45000, // 连接超时时间
    transports: ['websocket', 'polling'], // 优先使用websocket，降级到polling
    maxHttpBufferSize: 1e6, // 设置消息大小限制
    allowEIO3: true // 允许Engine.IO 3兼容模式
});
let users = {}; // 用于记录连接的用户和用户名的对应关系
const { getFormattedDate } = require('./timetrans')
let clientCount = 0
// 定义特殊社区聊天室ID
const COMMUNITY_CHAT_ID = 999999;

// 替换单连接为连接池
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'Baoyu273511a',
    database: 'film_db',
    waitForConnections: true,
    connectionLimit: 20, // 增加连接限制
    queueLimit: 0,
    // 优化连接池配置
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000 // 10秒
});

// 获取promise接口以使用async/await
const promisePool = pool.promise();

const port = 3000

// 跨域资源共享 (CORS) 配置，允许前端发起跨域请求
app.use(cors({
    origin: ['http://8.153.74.243', 'http://localhost'],  // 添加前端服务器地址
    credentials: true,  // 允许携带 Cookie
    methods: ['GET', 'POST', 'OPTIONS'],  // 允许的请求方法
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']  // 允许的请求头
}
));

// 会话中间件
app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,  // 使用 HTTPS 时设置为 true
        httpOnly: true,
        maxAge: 1000 * 60 * 60  // 1 小时
    }
}));

app.use(bodyParser.json())

app.options('*', cors());

// 注册路由优化
app.post('/register', async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "用户名和密码不能为空"
        })
    }

    try {
        // 检查用户名是否已经存在
        const [results] = await promisePool.query('SELECT 1 FROM users WHERE name = ? LIMIT 1', [username]);

        if (results.length > 0) {
            // 用户名已存在
            return res.status(409).json({ success: false, message: '用户名已存在，请选择其他用户名' });
        }

        // 加密密码
        const hashedPassword = await bcrypt.hash(password, 10);

        // 插入用户到数据库
        await promisePool.query('INSERT INTO users (name,password) VALUES (?,?)', [username, hashedPassword]);

        console.log('用户注册成功');
        return res.status(201).json({ success: true, message: '注册成功' });
    } catch (error) {
        console.error('注册过程中出错: ', error);
        return res.status(500).json({ success: false, message: '服务器错误' });
    }
})

// 登陆路由优化
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // 查询用户
        const [results] = await promisePool.query('SELECT * FROM users WHERE name = ?', [username]);

        if (results.length === 0) {
            return res.status(401).json({ success: false, message: '用户名或密码不正确' });
        }

        const user = results[0];

        // 验证密码
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: '用户名或密码不正确' });
        }

        console.log('用户登陆成功');
        return res.json({ success: true });
    } catch (error) {
        console.error('登录过程中出错: ', error);
        return res.status(500).json({ success: false, message: '服务器错误' });
    }
});

// 添加简单健康检查端点
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// 添加Socket.IO连接日志中间件
io.use((socket, next) => {
    const username = socket.handshake.query.username;
    const movieId = socket.handshake.query.movieId;
    const clientIP = socket.handshake.address;
    const transport = socket.conn.transport.name; // websocket或polling

    console.log(`连接请求 - IP: ${clientIP}, 用户: ${username}, 电影ID: ${movieId}, 传输方式: ${transport}`);
    console.log(`连接查询参数:`, socket.handshake.query);
    console.log(`连接请求头:`, socket.handshake.headers);

    next();
});

// 监听Socket.IO服务器级别事件
io.engine.on('initial_headers', (headers, req) => {
    console.log('初始化头信息处理:', Object.keys(headers));
});

io.engine.on('headers', (headers, req) => {
    console.log('响应头信息处理:', Object.keys(headers));
});

// 优化Chat Room连接处理
io.on('connection', socket => {
    try {
        const usrname = socket.handshake.query.username
        const movieId = socket.handshake.query.movieId // 新增：获取电影ID
        const socketId = socket.id;
        const transport = socket.conn.transport.name;

        console.log(`连接成功 - SocketID: ${socketId}, 用户: ${usrname}, 电影ID: ${movieId}, 传输方式: ${transport}`);

        // 处理参数缺失情况
        if (!usrname || !movieId) {
            console.log(`连接参数缺失 - SocketID: ${socketId}`);
            socket.emit('error', {
                message: '连接参数缺失',
                code: 'PARAMS_MISSING',
                socketId: socketId,
                timestamp: Date.now()
            });
            socket.disconnect();
            return;
        }

        users[socket.id] = {
            username: usrname,
            movieId: movieId,
            connectionTime: Date.now(),
            transport: transport
        } // 保存用户信息和所在聊天室
        console.log(`用户加入聊天室 - SocketID: ${socketId}, 用户: ${usrname}, 电影ID: ${movieId}, 当前总连接数: ${clientCount + 1}`);

        clientCount++

        // 加入特定电影的聊天室
        socket.join(`movie_${movieId}`);
        console.log(`用户已加入房间 - 房间ID: movie_${movieId}, 用户: ${usrname}`);

        // 处理连接成功
        socket.emit('connect_success', {
            message: '连接成功',
            socketId: socket.id,
            timestamp: Date.now(),
            transportType: transport,
            serverTime: getFormattedDate(),
            roomId: `movie_${movieId}`,
            activeUsers: io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 1
        });

        // 连接状态监测 - 定期发送连接状态信息到客户端
        const statusInterval = setInterval(() => {
            if (socket.connected) {
                socket.emit('connection_status', {
                    connected: true,
                    socketId: socket.id,
                    timestamp: Date.now(),
                    transportType: socket.conn.transport.name,
                    pingInterval: io.engine.pingInterval,
                    pingTimeout: io.engine.pingTimeout
                });
            } else {
                clearInterval(statusInterval);
            }
        }, 30000); // 每30秒发送一次状态

        // 延迟加载聊天记录，先建立连接
        setTimeout(() => {
            // 优化查询 - 限制返回的消息数量
            promisePool.query('SELECT * FROM messages WHERE movie_id = ? ORDER BY id DESC LIMIT 50', [movieId])
                .then(([results]) => {
                    // 反转结果以保持时间顺序
                    socket.emit('load previous messages', results.reverse());
                    // 自己查看：发送该聊天室在线人数
                    const roomCount = io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 0;
                    socket.emit("show count", roomCount);
                    // 通知前端加载完成
                    socket.emit('messages_loaded', {
                        count: results.length,
                        roomId: `movie_${movieId}`,
                        timestamp: Date.now()
                    });
                })
                .catch(err => {
                    console.log("查询聊天记录时出错：" + err.stack);
                    socket.emit('error', {
                        message: '加载聊天记录失败',
                        code: 'DB_ERROR',
                        details: err.message,
                        timestamp: Date.now()
                    });
                });
        }, 100); // 短暂延迟100ms，先确保连接建立

        // 向该电影聊天室广播用户加入消息
        io.to(`movie_${movieId}`).emit("login message", {
            msg: `${usrname}进入了聊天室！`,
            created_at: getFormattedDate(),
            movie_id: movieId
        })

        // 只向该电影聊天室广播人数
        io.to(`movie_${movieId}`).emit("show count", io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 0)

        // 监听客户端活动
        socket.on('client_activity', (data) => {
            console.log(`客户端活动 - SocketID: ${socket.id}, 用户: ${users[socket.id]?.username}, 活动: ${data.action}, 电影ID: ${users[socket.id]?.movieId}`);
            // 确认接收到活动信息
            socket.emit('activity_confirmed', {
                id: Date.now(),
                action: data.action
            });
        });

        // 监听前端错误报告
        socket.on('client_error', (data) => {
            console.log(`客户端错误 - SocketID: ${socket.id}, 用户: ${users[socket.id]?.username}, 错误: ${data.message}, 详情:`, data);
        });

        // 监听传输切换
        socket.conn.on('upgrade', (transport) => {
            console.log(`传输升级 - SocketID: ${socket.id}, 用户: ${users[socket.id]?.username}, 新传输方式: ${transport.name}`);
        });

        // 监听用户发送的消息保存到数据库并输出 - 使用连接池
        socket.on('chat message', async (data) => {
            try {
                const userInfo = users[socket.id];
                if (!userInfo) {
                    console.log(`消息处理失败 - SocketID: ${socket.id}, 原因: 用户未正确连接`);
                    socket.emit('error', { message: '用户未正确连接，请重新连接' });
                    return;
                }

                const username = userInfo.username;
                const movieId = data.movieId;

                // 添加日志以便调试
                console.log(`收到消息 - SocketID: ${socket.id}, 用户: ${username}, 电影ID: ${movieId}, 消息: ${data.msg}`);

                // 验证消息内容
                if (!data.msg || !data.movieId) {
                    socket.emit('error', { message: '消息格式不正确' });
                    return;
                }

                // 限制消息长度
                const message = data.msg.slice(0, 500); // 限制消息最大长度为500字符

                // 使用异步/等待减少回调嵌套
                try {
                    await promisePool.query('INSERT INTO messages (msg, created_at, color, username, movie_id) VALUES (?, ?, ?, ?, ?)',
                        [message, data.created_at, data.color, username, movieId]);

                    console.log(`消息记录 ${message} 已保存到数据库，电影ID: ${movieId}`);

                    // 向特定电影聊天室广播消息
                    io.to(`movie_${movieId}`).emit('chat message', {
                        ...data,
                        msg: message,
                        username: username,
                        movie_id: movieId
                    });

                    // 确认消息已保存
                    socket.emit('message_confirmed', { id: Date.now() });
                } catch (err) {
                    console.error('保存聊天记录时出错: ' + err.stack);
                    socket.emit('error', { message: '消息发送失败，请重试' });
                }
            } catch (error) {
                console.error(`消息处理错误 - SocketID: ${socket.id}, 错误:`, error);
                socket.emit('error', { message: '服务器处理消息错误' });
            }
        });

        // 添加重连接机制
        socket.on('reconnect_attempt', (attemptNumber) => {
            console.log(`重连尝试 - 用户: ${users[socket.id]?.username}, SocketID: ${socket.id}, 尝试次数: ${attemptNumber}`);
        });

        socket.on('reconnect', () => {
            console.log(`重连成功 - SocketID: ${socket.id}, 用户: ${users[socket.id]?.username}`);
            socket.emit('reconnect_success', { message: '重连成功' });
        });

        socket.on('reconnect_error', (error) => {
            console.log(`重连失败 - SocketID: ${socket.id}, 错误:`, error);
        });

        socket.on('reconnect_failed', () => {
            console.log(`重连彻底失败 - SocketID: ${socket.id}`);
        });

        // 添加心跳检测
        socket.on('ping', () => {
            console.log(`心跳ping - SocketID: ${socket.id}, 用户: ${users[socket.id]?.username}`);
            socket.emit('pong', { timestamp: Date.now() });
        });

        // 当网络延迟超过阈值时通知客户端
        socket.conn.on('packetCreate', (packet) => {
            if (socket.conn._lastPong) {
                const latency = Date.now() - socket.conn._lastPong;
                if (latency > 1000) { // 延迟超过1秒
                    socket.emit('network_latency', {
                        latency,
                        timestamp: Date.now()
                    });
                }
            }
        });

        socket.on('disconnect', (reason) => {
            const userInfo = users[socket.id];
            console.log(`连接断开 - SocketID: ${socket.id}, 原因: ${reason}`);

            // 清除状态监测
            clearInterval(statusInterval);

            if (userInfo) {
                const movieId = userInfo.movieId;
                const username = userInfo.username;

                console.log(`用户离开聊天室 - SocketID: ${socket.id}, 用户: ${username}, 电影ID: ${movieId}, 剩余连接数: ${clientCount - 1}`);

                socket.leave(`movie_${movieId}`);
                io.to(`movie_${movieId}`).emit("login message", {
                    msg: `${username}离开了聊天室...`,
                    created_at: getFormattedDate(),
                    movie_id: movieId
                });

                // 更新并广播该电影聊天室的人数
                const roomCount = io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 0;
                io.to(`movie_${movieId}`).emit("show count", roomCount);
                console.log(`聊天室人数更新 - 房间ID: movie_${movieId}, 当前人数: ${roomCount}`);

                delete users[socket.id];
            }

            clientCount--;
        });

        // 监听连接错误
        socket.on('error', (error) => {
            console.error(`套接字错误 - SocketID: ${socket.id}, 错误:`, error);
        });
    } catch (error) {
        console.error(`连接处理异常 - SocketID: ${socket.id}, 错误:`, error);
        socket.emit('error', {
            message: '服务器连接处理错误',
            code: 'SERVER_ERROR',
            details: error.message,
            timestamp: Date.now()
        });
        socket.disconnect();
    }
});

// 监听Socket.IO错误
io.engine.on('connection_error', (err) => {
    console.log(`IO引擎连接错误:`, err);
});

// 添加周期性清理断开但未正确关闭的连接
setInterval(() => {
    for (const [socketId, socket] of io.sockets.sockets) {
        if (!socket.connected) {
            console.log(`清理断开的连接: ${socketId}`);
            delete users[socketId];
        }
    }

    // 输出连接统计信息
    const stats = getConnectionStats();
    console.log(`连接统计: 总连接数: ${stats.totalConnections}, 活跃房间: ${Object.keys(stats.activeRooms).length}`);
    console.log(`传输统计: WebSocket: ${stats.transportStats.websocket}, Polling: ${stats.transportStats.polling}, 未知: ${stats.transportStats.unknown}`);
}, 60000); // 每分钟清理一次

// 添加服务器状态监控
setInterval(() => {
    const activeConnections = Object.keys(users).length;
    const activeRooms = io.sockets.adapter.rooms.size;
    console.log(`服务器状态: 活跃连接 ${activeConnections}, 活跃房间 ${activeRooms}`);
}, 300000); // 每5分钟记录一次服务器状态


// 监控函数 - 记录活跃连接信息
function getConnectionStats() {
    const stats = {
        totalConnections: Object.keys(users).length,
        activeRooms: {},
        transportStats: {
            websocket: 0,
            polling: 0,
            unknown: 0
        }
    };

    // 计算每个房间的连接数
    for (const socketId in users) {
        const user = users[socketId];
        const roomId = `movie_${user.movieId}`;

        if (!stats.activeRooms[roomId]) {
            stats.activeRooms[roomId] = 0;
        }
        stats.activeRooms[roomId]++;

        // 统计传输类型
        if (user.transport) {
            if (stats.transportStats[user.transport] !== undefined) {
                stats.transportStats[user.transport]++;
            } else {
                stats.transportStats.unknown++;
            }
        } else {
            stats.transportStats.unknown++;
        }
    }

    return stats;
}

// 添加连接详情端点
app.get('/connection-stats', (req, res) => {
    try {
        const stats = getConnectionStats();
        res.json({
            success: true,
            timestamp: Date.now(),
            stats
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: '获取连接统计信息失败',
            error: error.message
        });
    }
});

// 合并HTTP和Socket.IO服务器到同一个端口以提高效率
server.listen(port, '0.0.0.0', () => {
    console.log(`服务器运行在 0.0.0.0:${port}`);
});