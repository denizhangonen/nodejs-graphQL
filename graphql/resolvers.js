const bcrypt = require("bcryptjs");
const validator = require("validator");

const User = require("../models/user");

module.exports = {
  createUser: async function({ userInput }, req) {
    //#region input data validations
    const errors = [];

    if (!validator.isEmail(userInput.email)) {
      errors.push({ message: "E-mail is invalid." });
    }

    if (
      validator.isEmpty(userInput.password) ||
      !validator.isLength(userInput.password, { min: 3 })
    ) {
      errors.push({ message: "password is invalid." });
    }

    if (errors.length > 0) {
      const error = new Error("invalid input");
      throw error;
    }

    //#endregion input data validations
    const existingUser = await User.findOne({ email: userInput.email });
    if (existingUser) {
      const error = new Error("User already exists.");
      throw error;
    }
    const hashedPw = await bcrypt.hash(userInput.password, 12);

    const user = new User({
      email: userInput.email,
      name: userInput.name,
      password: hashedPw
    });

    const createUser = await user.save();
    return {
      ...createUser._doc,
      _id: createUser._id.toString()
    };
  }
};
