const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'мій-дуже-довгий-секретний-ключ';
const COOKIE_NAME = 'token';
app.use(express.json())
app.use(cookieParser())
app.use(express.static(path.join(__dirname,'public')))
const users =[]
const cookieOptions = {
    httpOnly : true ,
    sameSite :strict,
    maxAge : 60 *60*1000 //одна година 
}
function createToken (user){
    return jwt.sign(
        { id:user.id ,username:user.username},
        JWT_SECRET,
        {expiresIn:'1h'}
    )
}
function requireAuth(req,res,next){
    const token =req.cookies[COOKIE_NAME]
    if(!token){
        return res.status(401).json({error:'потрібно увійти'})
    }
    try{
        req.user =jwt.verify(token,JWT_SECRET);
        next()
    }
    catch{
        res.clearCookie(COOKIE_NAME)
        res.status(401).json({error:'сесія закінчилася'})
    }
}
app.post('/api/register',async (req,res)=>{
    const { username,password }=req.body
    if(!username || !password || password.length < 6){
        return res.status(400).json({error:'логін і пароль повинні містити від 6 символів'})
    }
    if(users.find(u => u.username === username)){
        return res.status(409).json({error:'такий логін вже є'})
    }
    const passworHash = await bcrypt.hash(password,10);
    const user = {id: Date.now().toString(), username,passwordHash};
    users.push(user)
    res.cookie(COOKIE_NAME,createToken(user),cookieOptions);
    res.status(201).json({username})
})
app.post('/api/login',async (req,res)=>{
    const {username ,password} =req.body;
    const user = users.find(u=> u.username === username)
    const ok =user && await bcrypt.compare(password,user.passwordHash)
})