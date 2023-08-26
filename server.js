const express = require("express");
const mongoose = require("mongoose");
require('dotenv').config();
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const FacebookStrategy=require("passport-facebook").Strategy;
var findOrCreate = require('mongoose-findorcreate');
const multer = require('multer');
const sharp = require('sharp');
const axios = require('axios');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
const MongoStore = require('connect-mongo');
const  cookieParser = require('cookie-parser')
const cors = require('cors');
const app = express();
app.set('trust proxy', 1);
const url=process.env.Mongodb;
mongoose.connect(url, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
app.use(cookieParser())
app.use('/api/edited-images', express.static('uploads'));

app.use((req, res, next) => {
  console.log("Session Data:", req.session);
  next();
});

app.use(cors({
  origin: 'http://localhost:3001',
  credentials: true
}));

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  name: 'MyauthenticationCookieName',
  proxy: true,
  cookie:{
     httpOnly: true,
      maxAge: 3600000,
    httpOnly: true, 
    secure: true, 
    sameSite: 'none'
       },
   store: MongoStore.create({
    mongoUrl: url,
    ttl: 14 * 24 * 60 * 60 // = 14 days. Default
  }),
    secret: process.env.Secret,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

;

const userSchema = new mongoose.Schema({
  email: String, // Unique identifier for local authentication
  googleId: String, // Unique identifier for Google authentication
  githubId: String, 
  username:String,// Unique identifier for GitHub authentication
  facebookId: String, // Unique identifier for Facebook authentication
  name: String,
  password: String,
  profileUrl: String,
  bio:String,
  phone:String
});



passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user._id,
        
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.post("/authproject/register/", async (req, res) => {
    try {
       

        const { username, password } = req.query;

        if (!username) {
            return res.status(400).send("Username is required.");
        }
       const  localId=password;
        await User.register({ username }, password);

        passport.authenticate("local")(req, res, () => {
            res.send("authenticated successfully");
        });
    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

app.post("/authproject/login/", (req, res) => {
    const  {email,password}=req.query;
    const user= new User({
        email:email,
        password:password
     });
     req.login(user,(err)=>{
        if (err){console.log(err);
        res.send (err);
        }
        else {
            passport.authenticate("local")(req,res,()=>{
                res.send("Authenticated");
            })
        }
     })
});
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.Client_secret,
    callbackURL: "https://authenticationapp-tgnl.onrender.com/auth/google/secrets",
    scope: ['profile', 'email'] 
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    const email = profile.emails[0].value;
    User.findOrCreate({ googleId: profile.id,email:email,profileUrl:profile.photos[0].value,name:profile.displayName,username:email }, function (err, user) {
        
      return cb(err, user);
    });
  }
));
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile','email'] }));
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/register' }),
  function(req, res) {
   res.redirect("http://localhost:3001/successauth");
  });
  passport.use(new GitHubStrategy({
    clientID:process.env.Client_id_github,
    clientSecret: process.env.Client_secret_github,
    callbackURL: "https://authenticationapp-tgnl.onrender.com/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    console.log(profile);
    User.findOrCreate({ githubId: profile.id,username:profile.username,profileUrl:profile.photos[0].value }, function (err, user) {
      return done(err, user);
    });
  }
));
app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
  
       res.redirect("http://localhost:3001/successauth");
   
  });
  app.get("/info", async (req, res) => {
    if (req.isAuthenticated()) {
      try {
        
        const user = await User.findById(req.user.id);
        if (user) {
          res.send(user);
        } else {
          res.status(404).send("User not found");
        }
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send("Internal Server Error");
      }
    } else {
      res.send("You should log in");
    }
  });
  passport.use(new FacebookStrategy({
    clientID: process.env.Fb_App_id,
    clientSecret: process.env.Fb_Client_token,
  
    callbackURL: "https://authenticationapp-tgnl.onrender.com/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos', 'email'],
    scope: ['email', 'public_profile']
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ facebookId: profile.id ,username:profile.displayName,email:profile.emails[0].value}, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
  
   res.redirect("http://localhost:3001/successauth");
  });

  app.post("/updateUser/:userId", async (req, res) => {
    if (req.isAuthenticated()){
      console.log(req.body.data);
      const updatedData=req.body.data;
      const userId=req.body.data._id;
      try {
      
        const updatedUser = await User.findByIdAndUpdate(userId, updatedData, { new: true });
    
        if (updatedUser) {
          res.send({ message: "User updated successfully", user: updatedUser });
        } else {
          res.status(404).send({ message: "User not found" });
        }
      } catch (error) {
        console.error("Error updating user:", error);
        res.status(500).send({ message: "Internal Server Error" });
      }
    }
    else {
      res.send("Unautherized");
    }
 
  });
  

app.get("/logout",(req,res)=>{
    req.logout((err)=>{
        if (err){console.log(err);}
        else {res.send("logged out successufly");}
    });
    
    });
    


    
    app.post('/api/upload', upload.single('image'), async (req, res) => {
      try {
        let inputImageBuffer;
    
        if (req.file) {
          inputImageBuffer = req.file.buffer;
        } else if (req.body.imageUrl) {
          const response = await axios.get(req.body.imageUrl, { responseType: 'arraybuffer' });
          inputImageBuffer = Buffer.from(response.data, 'binary');
        } else {
          return res.status(400).json({ error: 'No image provided.' });
        }
        const editedImageFilename = `edited-${Date.now()}.jpg`;
        const editedImagePath = `uploads/${editedImageFilename}`;
        await sharp(inputImageBuffer)
          .resize(300, 300)
          .toFile(editedImagePath);
        
        // Serve the edited image URL
        const editedImageUrl = `/api/edited-images/${editedImageFilename}`;
    
        return res.status(200).json({ editedImageUrl });
      } catch (error) {
        console.error('Error editing image:', error);
        return res.status(500).json({ error: 'Internal server error.' });
      }
    });
    

    

     
app.listen(process.env.PORT || 3000, () => {
    console.log("Server is running on port 3000");
});
