const User =require('../models/UserDetails');
const bcrypt = require('bcrypt');
const jwt= require('jsonwebtoken')
const asyncHandler = require('express-async-handler');
require('dotenv').config();

const login = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ message: "All fields are required" });

    const foundUser = await User.findOne({ email }).exec();

    if (!foundUser || !foundUser.active) return res.status(401).json({ message: "Unauthorized" });

    const match = await bcrypt.compare(password, foundUser.password);

    if (!match) return res.status(401).json({ message: "Unauthorized" });

    const accessToken = jwt.sign({
        "UserInfo": {
            "username": foundUser.email,
            "roles": foundUser.roles
        }
    },
    process.env.ACCESS_TOKEN_SECRET, { expiresIn: "7d" });

    const refreshToken = jwt.sign({
        "username": foundUser.email 
    },
    process.env.REFRESH_TOKEN_SECRET, { expiresIn: "30d" });

    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', 
        sameSite: 'None',
        maxAge: 7 * 60 * 60 * 1000
    });

    res.json({ accessToken });
});

const refresh = async (req, res) => {
    const cookies = req.cookies;

    if (!cookies?.jwt) return res.status(401).json({ message: "Unauthorized" });

    const refreshToken = cookies.jwt;

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, decoded) => {
        if (err) return res.status(403).json({ message: "Forbidden" });

        const foundUser = await User.findOne({ email: decoded.email });

        if (!foundUser) return res.status(401).json({ message: "Unauthorized" });

        const accessToken = jwt.sign({
            "userInfo": {
                "email": foundUser.email, // Fixed space issue
                "roles": foundUser.roles
            }
        },
        process.env.ACCESS_TOKEN_SECRET, { expiresIn: "2m" });

        res.json({ accessToken });
    });
};





const logout = (req, res)=>{
    const cookies = req. cookies

    if(!cookies?.jwt) return res.sendStatus(204);
    res.clearCookie('jwt', {httpOnly: true, sameSite: 'None', secure: true})

    res.json({message:" Cookie cleared"})
}



module.exports = {
   login,
   refresh,
   logout
}