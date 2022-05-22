//jshint esversion:6
require('dotenv').config()
const express = require("express")
const bodyParser = require("body-parser")
const ejs = require("ejs")
const  mongoose = require("mongoose")
const encrypt = require("mongoose-encryption")

const app = express()

console.log(process.env.SECRET);

app.use(express.static('public'))
app.set('view engine', 'ejs')
app.use(bodyParser.urlencoded({extended: true}))

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser:true})

//DATABASE ---------------------------------------------

const userSchema = new mongoose.Schema({
    email:String,
    password:String
})

userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields: ['password']})

const User = new mongoose.model("User",userSchema)

//ROUTES -----------------------------------------------

app.get("/",(req,res) => {
    res.render("home")
})

app.route("/login")

.get((req,res) => {
    res.render("login")
})

.post((req,res) => {
    const username = req.body.username
    const password = req.body.password

    User.findOne({email:username},(err,content) => {
        if(!err){
            if(content){
                if(content.password === password){
                    res.render("secrets")
                }
            }
        }
    })

})

app.route("/register")

.get((req,res) => {
    res.render("register")
})

.post((req,res) => {
    const username = req.body.username
    const password = req.body.password

    const newUser = new User({
        email: username,
        password: password
    })

    newUser.save((err) => {
        if(!err){
            res.render("secrets")
        }else{
            res.send(err)
        }
    })

})


//LISTENING PORTS ------------------------------------

app.listen(3000,() => {
    console.log("Running on port 3000");
})