const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

dotenv.config();

const app = express();
const PORT = 3001;
const JWT_SECRET = 'thisismysecret';

mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('MongoDB connected Sucessfully'))
.catch(err => console.error('MongoDB connection error: ', err));

app.use(express.json());
app.use(cookieParser());

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Register / Login Users 

app.post('/auth', async (req, res) => {
    const { username, password } = req.body;

    let user = await User.findOne({ username });

    try {
        if (!user) {
            const hashedPassword = await bcrypt.hash(password, 10);
            user = new User({ username, password: hashedPassword });
            await user.save();
        } else {
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(403).json({ message: 'Invalid username or password' });
            } 
        }

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        const accessToken = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '15m' });

        res.json({ message : 'Authenticated Successfully' });
    } catch (err) {
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.get('/logout', async (req, res) => {
    res.clearCookie('accessToken');
    res.json({ message: 'Logged out Successfully' });
});

app.listen(PORT, () => {
    console.log(`Server is listening on ${PORT}`);
});


