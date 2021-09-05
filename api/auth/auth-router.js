const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken")
const Users = require('../users/users-model.js');


router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

    // let user = req.body;

    // const rounds = process.env.BCRYPT_ROUNDS || 8;
    // const hash = bcrypt.hashSync(user.password, rounds);

    // user.password = hash

    // Users.add(user)
    //   .then(saved => {
    //     res.status(201).json(saved)
    //   })
    //   .catch(next);

    try{
      const hash = bcrypt.hashSync(req.body.password, 8)
      const newUser = await Users.add({username: req.body.username, password: hash, role_name: req.body.role_name})
      const user = await Users.findBy({ username: req.body.username})
      console.log(user)
      res.status(201).json({
        username: user[0].username, 
        user_id: user[0].user_id, 
        role_name: user[0].role_name
      })
    }
    catch(err){
      next(err)
    } 
}); 


router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    let { username, password } =req.body;

    Users.findBy({ username })
      .then(([user]) =>{
        if (user && bcrypt.compareSync(password, user.password)){
          const token = makeToken(user)
          res.status(200).json({
            message: `${user.username} is back!`,
            token
          });
        }
        else{
          next({status: 401, message: 'Invalid Credentials'})
        }
      })
});

function makeToken(user){
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn: "1d"
  }
  return jwt.sign(payload, JWT_SECRET,options)
}

module.exports = router;
