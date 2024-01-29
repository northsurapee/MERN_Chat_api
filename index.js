const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv"); 
const User = require("./models/User")
const bcrypt = require("bcryptjs");
const ws = require("ws");
const Message = require("./models/Message");
const userModel = require("./models/User");
const {S3Client, PutObjectCommand} = require("@aws-sdk/client-s3");
const mime = require('mime-types');

/// INITIAL CONFIG
dotenv.config();
mongoose.connect(process.env.MONGO_URL);
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);
const bucket = "mern-chat";
const clientURL = (process.env.NODE_ENV === "development" ? process.env.DEV_CLIENT_URL : process.env.PRO_CLIENT_URL);
const PORT = process.env.PORT || 4040;

/// CREATE EXPRESS APP
const app = express();
app.use(express.json())
app.use(cookieParser());
app.use(
    cors({
      credentials: true,
      origin: [clientURL],
    }),
  );

//UPLOAD TO S3
async function uploadToS3(fileName, mimetype, bufferData) {
    const client = new S3Client({
        region: "ap-southeast-1",
        credentials: {
            accessKeyId: process.env.S3_ACCESS_KEY,
            secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
        },
    });
    await client.send(new PutObjectCommand({
        Bucket: bucket,
        Body: bufferData,
        Key: fileName,
        ContentType: mimetype,
        ACL: "public-read",
    }));
}

// Endpoint for test
app.get("/", (req, res) => {
    res.status(201).json("test");
});

// Endpoint for verify cookies (use in context provider)
app.get("/profile", (req, res) => {
    const token = req.cookies?.token;
    if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) throw err;
            res.json(userData);
        });
    } else {
        res.status(401).json("no token");
    }
});

// Endpoint for register
app.post("/register", async (req, res) => {
    const {username, password} = req.body;
    try {
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
        // 1) Creat new User document in database
        const createdUser = await User.create({
            username: username, 
            password: hashedPassword,
        });
        // 2) Sign Id & username to token, then set it as client cookies
        // Respone back a json containing Object id.
        jwt.sign({userId:createdUser._id, username}, jwtSecret, {}, (err, token) => {
            if (err) throw err;
            res.cookie('token', token).status(201).json({
                id: createdUser._id,
            });
        });
    } catch(err) {
        if (err) throw err;
        res.status(500).json("error");
    }
})

// Endpoint for login
app.post("/login", async (req, res) => {
    const {username, password} = req.body;
    const foundUser = await User.findOne({username}); // 1) find user in database
    if (foundUser) {
        // 2) Check password
        const passOK = bcrypt.compareSync(password, foundUser.password);
        if (passOK) {
             // 3) Like Register (2)
            jwt.sign({userId:foundUser._id, username}, jwtSecret, {}, (err, token) => {
                if (err) throw err;
                res.cookie('token', token).status(201).json({
                    id: foundUser._id,
                });
            });
        }
    }
});

// Vefity token to get our userData
async function getUserDataFromRequest(req) {
    return new Promise((resolve, reject) => {
        const token = req.cookies?.token;
        if (token) {
            jwt.verify(token, jwtSecret, {}, (err, userData) => {
                if (err) throw err;
                resolve(userData);
            });
        } else {
            reject("no token");
        }   
    });
}

// End point for get all messages
app.get("/messages/:userId", async (req, res) => {
    const {userId} = req.params; // Receive selectedUser from req
    const userData = await getUserDataFromRequest(req); // Vefity token to get our userData
    const ourUserId = userData.userId;
    // Find messages that we send and selectedUser receive.
    const messages = await Message.find({
        sender:{$in: [userId, ourUserId]},
        recipient:{$in: [userId, ourUserId]},
    }).sort({createdAt: 1});
    // Respone message back
    res.json(messages);
});

// End point for get all users
app.get("/people", async (req, res) => {
    const users = await User.find({}, {"_id":1, username: 1});
    res.json(users);
});

// End point for logout
app.post("/logout", async (req, res) => {
    res.cookie('token', "").status(201).json("ok"); // Clear cookies
});

// Server listening at localhost:4040
const server = app.listen(PORT);

// ---------------------------------------------------------------------------------------

// Websocket server
const wss = new ws.WebSocketServer({server});


wss.on("connection", (connection, req) => {

    // Notify everyone about online people (when someone connect or disconnect)
    function notifyAboutOnlinePeople() {{
        [...wss.clients].forEach(client => {
            client.send(JSON.stringify({
                online: [...wss.clients].map(c => ({userId: c.userId, username: c.username}))
            }));
        });
    }}

    // Killing old connection
    connection.isAlive = true; // after someone connected
    connection.timer = setInterval(() => { // check for heartbeat (ping-pong) every 5 second
        connection.ping();
        connection.deathTimer = setTimeout(() => { // if no pong after 1 second 
            connection.isAlive = false;
            clearInterval(connection.timer); // clear heartbeat function
            connection.terminate(); // terminate connection (free memory from server)
            notifyAboutOnlinePeople(); // respone new online clinets to everyone's frontend
            console.log("dead");
        }, 1000);
    }, 5000);

    connection.on("pong", () => {
        clearTimeout(connection.deathTimer);
    });

    // Read username and id of this connection's client
    const cookies = req.headers.cookie;
    if (cookies) {
        const tokenCoolieString = cookies.split(";").find(str => str.startsWith("token="));
        if (tokenCoolieString) {
            const token = tokenCoolieString.split("=")[1];
            if (token) {
                jwt.verify(token, jwtSecret, {}, (err, userData) => {
                    if (err) throw err;
                    const {userId, username} = userData;
                    connection.userId = userId;
                    connection.username = username;
                });
            }
        }
    }

    // Received message from sender client -> Save on database -> Send back to recipient
    connection.on("message", async (message) => {
        const messageData = JSON.parse(message.toString()); // parse message
        const {recipient, text, file} = messageData; // extract message
        let fileName = null;
        // console.log(file);
        if (file) { 
            const parts = file.name.split(".");
            const ext = parts[parts.length - 1];
            fileName = Date.now() + "." + ext;
            const bufferData = Buffer.from(file.data.split(",")[1], "base64");
            // Upload to s3
            const mimeType = mime.lookup(file.name);
            await uploadToS3(fileName, mimeType, bufferData);
        }
        if (recipient && (text || file)) {
            // Create message document on database
            const messageDoc = await Message.create({
                sender:connection.userId,
                recipient,
                text,
                file: file ? fileName : null,
            });
            // Filter clients that is recipient, then send message with text or fileName to them
            [...wss.clients]
                .filter(c => c.userId === recipient)
                .forEach(c => c.send(JSON.stringify({
                    text, 
                    sender:connection.userId,
                    recipient,
                    file: file ? fileName : null,
                    _id:messageDoc._id,
                })));
        }
    });

    // Notify everyone about online people (when someone connects)
    notifyAboutOnlinePeople();
});