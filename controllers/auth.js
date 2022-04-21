const User = require("../models/User");
const jwt = require("jsonwebtoken");
const { BadRequestError, UnauthenticatedError } = require("../errors");

const registerUser = async (req, res) => {
  const user = await User.create({ ...req.body });
  const token = user.createJWT();
  res.status(201).json({ user: { name: user.name }, token });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new BadRequestError("please provide email and password");
  }
  const user = await User.findOne({ email });
  //if the user doesn't exists we throw an unauthenticated error
  if (!user) {
    throw new UnauthenticatedError("invalid credentials");
  }
  //compare password
  const isPasswordCorrect=await user.comparePasswords(password)
  if(!isPasswordCorrect){
    throw new UnauthenticatedError("invalid credentials");
  }
  //if the user exists we want to create the token and send it back
  const token = user.createJWT();
  res.status(200).json({ user: { name: user.name }, token });
};

module.exports = { registerUser, login };
