const express = require('express');
const dotenv = require('dotenv');
dotenv.config()
const cors = require('cors');
const app = express();
const cookieParser = require('cookie-parser')
const {connectDb} = require('./config/dbConfig')
const userRoutes = require('./routes/userRoutes');
const { verifyUser } = require('./controller/UserController');
app.use(express.json());
app.use(cookieParser())
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    optionsSuccessStatus: 200
}))
const PORT = process.env.PORT || 3000;
connectDb();

app.get('/', (req, res) => {
  res.send('Successfully connected to the server');
});

//ROUTES
app.use('/api/v1/user', userRoutes)
app.get('/token/:verifyToken', verifyUser)

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});