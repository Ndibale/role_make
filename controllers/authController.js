const User =require('../models/UserDetails');
const bcrypt = require('bcrypt');
const jwt= require('jsonwebtoken')
const asyncHandler = require('express-async-handler');
require('dotenv').config();


const login = asyncHandler(async (req,res)=>{
    const { username, password } = req.body;

    if(!username || !password) return res.status(400).json({message:"All fields are required"});

    const foundUser = await User.findOne({username}).exec();

    if(!foundUser || !foundUser.active) return res.status(401).json({message:"Unauthorized"});

    const match = await bcrypt.compare(password, foundUser.password);

    if(!match) return res.status(401).json({message:"Unauthorized"});




const accessToken = jwt.sign({
    "UserInfo": {
        "username ":foundUser.username,
        "roles": foundUser.roles
    }
},
    process.env.ACCESS_TOKEN_SECRET, {expiresIn: "2m"}

)



const refreshToken = jwt.sign({
    "username": { "username ":foundUser.username }
},
    process.env.REFRESH_TOKEN_SECRET , {expiresIn: "1d"}

);

res.cookie('jwt', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
    maxAge: 7*60*60*1000
});

// Send a token containing username and role
res.json({accessToken})

});


const refresh = (req, res)=>{
    const cookies = req. cookies

    if(!cookies?.jwt) return res.status(401).json({message:"Unauthorized"});

    const refreshToken = cookies.jwt

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        asyncHandler(async(err, decoded)=>{
            if(err) return res.status(403).json({message:" Forbidden"});

            const foundUser = await User.findOne({username: decoded.username});

            if(!foundUser) return res.status(401).json({message: "Unauthorized"});

            const accessToken = jwt.sign({
                "userInfo":{
                    "username ":foundUser.username,
                    "roles": foundUser.roles
                }
            },
            process.env.ACCESS_TOKEN_SECRET, {expiresIn: "2m"}
            )

            res.json({accessToken});
        })
    )
}




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