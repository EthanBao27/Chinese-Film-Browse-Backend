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
    }
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
    connectionLimit: 10,
    queueLimit: 0
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

// Chat Room
io.on('connection', socket => {
    const usrname = socket.handshake.query.username
    const movieId = socket.handshake.query.movieId // 新增：获取电影ID

    users[socket.id] = { username: usrname, movieId: movieId } // 保存用户信息和所在聊天室
    console.log(`User ${usrname} connected to movie chat ${movieId}`);

    clientCount++

    // 加入特定电影的聊天室
    socket.join(`movie_${movieId}`);

    // 只加载该电影相关的聊天记录 - 使用连接池
    promisePool.query('SELECT * FROM messages WHERE movie_id = ? ORDER BY id ASC', [movieId])
        .then(([results]) => {
            socket.emit('load previous messages', results);
            // 自己查看：发送该聊天室在线人数
            const roomCount = io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 0;
            socket.emit("show count", roomCount);
        })
        .catch(err => {
            console.log("查询聊天记录时出错：" + err.stack);
        });

    // 向该电影聊天室广播用户加入消息
    io.to(`movie_${movieId}`).emit("login message", {
        msg: `${usrname}进入了聊天室！`,
        created_at: getFormattedDate(),
        movie_id: movieId
    })

    // 只向该电影聊天室广播人数
    io.to(`movie_${movieId}`).emit("show count", io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 0)

    // 监听用户发送的消息保存到数据库并输出 - 使用连接池
    socket.on('chat message', data => {
        const userInfo = users[socket.id];
        const username = userInfo.username;
        const movieId = data.movieId;

        // 添加日志以便调试
        console.log(`收到消息：${data.msg}，用户：${username}，电影ID：${movieId}`);

        promisePool.query('INSERT INTO messages (msg, created_at, color, username, movie_id) VALUES (?, ?, ?, ?, ?)',
            [data.msg, data.created_at, data.color, username, movieId])
            .then(result => {
                console.log(`消息记录 ${data.msg} 已保存到数据库，电影ID: ${movieId}`);

                // 向特定电影聊天室广播消息
                io.to(`movie_${movieId}`).emit('chat message', {
                    ...data,
                    username: username,
                    movie_id: movieId
                });
            })
            .catch(err => {
                console.error('保存聊天记录时出错: ' + err.stack);
            });
    });

    socket.on('disconnect', () => {
        const userInfo = users[socket.id];
        if (userInfo) {
            const movieId = userInfo.movieId;
            const username = userInfo.username;

            socket.leave(`movie_${movieId}`);
            io.to(`movie_${movieId}`).emit("login message", {
                msg: `${username}离开了聊天室...`,
                created_at: getFormattedDate(),
                movie_id: movieId
            });

            // 更新并广播该电影聊天室的人数
            const roomCount = io.sockets.adapter.rooms.get(`movie_${movieId}`)?.size || 0;
            io.to(`movie_${movieId}`).emit("show count", roomCount);

            delete users[socket.id];
        }

        clientCount--;
    })
})

// 合并HTTP和Socket.IO服务器到同一个端口以提高效率
server.listen(port, () => {
    console.log(`服务器运行在端口 ${port}`);
});