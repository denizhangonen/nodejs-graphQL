const bcrypt = require("bcryptjs");
const validator = require("validator");
const jwt = require("jsonwebtoken");

const User = require("../models/user");
const Post = require("../models/post");

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
      error.data = errors;
      error.code = 422;
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
  },
  login: async function({ email, password }, req) {
    // find the user
    const user = await User.findOne({ email: email });
    //return error if user not found
    if (!user) {
      const error = new Error("no user found.");
      error.code = 401;
      throw error;
    }
    // if user found with given email then verify the password
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      // Although we know password is wrong return a mismatch message
      const error = new Error("email and password mismatch.");
      error.code = 401;
      throw error;
    }

    const token = jwt.sign(
      {
        userId: user._id.toString(),
        email: user.email
      },
      "cicicat",
      { expiresIn: "1h" }
    );

    return { token: token, userId: user._id.toString() };
  },
  createPost: async function({ postInput }, req) {
    //check for authentication
    if (!req.isAuth) {
      const error = new Error("Not authenticated!");
      error.code = 401;
      throw error;
    }

    //#region data validation
    const errors = [];

    if (
      validator.isEmpty(postInput.title) ||
      !validator.isLength(postInput.title, { min: 3 })
    ) {
      errors.push({ message: "Title is invalid" });
    }

    if (
      validator.isEmpty(postInput.content) ||
      !validator.isLength(postInput.content, { min: 3 })
    ) {
      errors.push({ message: "Content is invalid" });
    }

    if (errors.length > 0) {
      const error = new Error("invalid input");
      error.data = errors;
      error.code = 422;
      throw error;
    }
    //#endregion data validation

    //get the user
    const user = await User.findById(req.userId);
    if (!user) {
      const error = new Error("invalid user");
      error.code = 401;
      throw error;
    }
    const post = new Post({
      title: postInput.title,
      content: postInput.content,
      imageUrl: postInput.imageUrl,
      creator: user
    });

    const createdPost = await post.save();
    //Add post to user doc
    user.posts.push(createdPost);
    await user.save();

    return {
      ...createdPost._doc,
      _id: createdPost._id.toString(),
      createdAt: createdPost.createdAt.toISOString(),
      updatedAt: createdPost.updatedAt.toISOString()
    };
  },
  posts: async function({ page }, req) {
    //check for authentication
    if (!req.isAuth) {
      const error = new Error("Not authenticated!");
      error.code = 401;
      throw error;
    }
    if (!page) {
      page = 1;
    }
    const perPage = 2;
    const totalPosts = await Post.find().countDocuments();

    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * perPage)
      .limit(perPage)
      .populate("creator");

    return {
      posts: posts.map(p => {
        return {
          ...p._doc,
          _id: p._id.toString(),
          createdAt: p.createdAt.toISOString(),
          updatedAt: p.updatedAt.toISOString()
        };
      }),
      totalPosts: totalPosts
    };
  },
  post: async function({ id }, req) {
    if (!req.isAuth) {
      const error = new Error("Not authenticated!");
      error.code = 401;
      throw error;
    }

    const post = await Post.findById(id).populate("creator");

    if (!post) {
      const error = new Error("No posts found!");
      error.code = 404;
      throw error;
    }

    return {
      ...post._doc,
      _id: post._id.toString(),
      createdAt: post.createdAt.toISOString(),
      updatedAt: post.updatedAt.toISOString()
    };
  },
  updatePost: async function({ id, postInput }, req) {
    if (!req.isAuth) {
      const error = new Error("Not authenticated!");
      error.code = 401;
      throw error;
    }

    const post = await Post.findById(id).populate("creator");
    if (!post) {
      const error = new Error("No posts found");
      error.code = 404;
      throw error;
    }

    if (post.creator._id.toString() !== req.userId.toString()) {
      const error = new Error("Not authorized");
      error.code = 403;
      throw error;
    }
    //#region data validation
    const errors = [];

    if (
      validator.isEmpty(postInput.title) ||
      !validator.isLength(postInput.title, { min: 3 })
    ) {
      errors.push({ message: "Title is invalid" });
    }

    if (
      validator.isEmpty(postInput.content) ||
      !validator.isLength(postInput.content, { min: 3 })
    ) {
      errors.push({ message: "Content is invalid" });
    }

    if (errors.length > 0) {
      const error = new Error("invalid input");
      error.data = errors;
      error.code = 422;
      throw error;
    }
    //#endregion data validation

    post.title = postInput.title;
    post.content = postInput.content;
    if (postInput.imageUrl !== "undefined") {
      post.imageUrl = postInput.imageUrl;
    }

    const updatedPost = await post.save();

    return {
      ...updatedPost._doc,
      _id: updatedPost._id.toString(),
      createdAt: updatedPost.createdAt.toISOString(),
      updatedAt: updatedPost.updatedAt.toISOString()
    };
  }
};
