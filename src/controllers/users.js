import { Pre_User } from "../models/users/pre_user.js";
import { User } from "../models/users/user.js";
import { schoolCheck } from "../checks/user_auth.js";
import { send_otp } from "../checks/send_otp.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Handle pre-registration
export const pre_register_post = async (req, res) => {
  const { email, password } = req.body;

  // Validate university email
  if (!schoolCheck(email)) {
    return res.json({ msg: "Invalid Email! Please Use Your University Email.", success: false });
  }

  // Check if email is already registered
  const existingUser = await User.findOne({ where: { email } });
  if (existingUser) {
    return res.json({ msg: "You Have Registered Already!", success: false });
  }

  // Check if email is in pre-registration database
  const preUser = await Pre_User.findOne({ where: { email } });

  // Generate OTP and hash password
  const userOtp = Math.floor(Math.random() * 999999);
  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(password, salt);

  try {
    if (preUser) {
      // Update existing pre-user
      preUser.set({ password: hashedPassword, otp: userOtp });
      await preUser.save();
    } else {
      // Create new pre-user
      await Pre_User.create({ email, password: hashedPassword, otp: userOtp });
    }

    // Send OTP and set cookies
    send_otp(email, userOtp);
    return res
      .cookie("email", email, { httpOnly: true })
      .cookie("password", hashedPassword, { httpOnly: true })
      .cookie("otp", userOtp, { httpOnly: true })
      .json({ msg: null, success: true });
  } catch (error) {
    console.error(error);
    return res.json({ msg: "Something Went Wrong! Please Try Again!", success: false });
  }
};

// Verify OTP
export const verify_otp_post = async (req, res) => {
  const { email, otp } = req.cookies;

  if (parseInt(req.body.otp) === otp) {
    return res
      .cookie("otp_verified", true, { httpOnly: true })
      .json({ msg: null, success: true });
  }

  return res.json({ msg: "Invalid OTP!", success: false });
};

// Resend OTP
export const resend_otp = async (req, res) => {
  try {
    const { email, otp } = req.cookies;
    if (!email || !otp) throw new Error("Missing email or OTP");

    const otpSent = await send_otp(email, otp);
    if (otpSent) {
      return res.json({ msg: "Check Your Inbox for OTP!" });
    }

    throw new Error("OTP Sending Failed");
  } catch (error) {
    return res.json({ msg: "Cannot Send OTP!" });
  }
};

// Complete registration
export const register_post = async (req, res) => {
  const { name, age, gender, school, batch, bio } = req.body;
  const { email, password, otp_verified } = req.cookies;

  if (!otp_verified) {
    return res.json({ msg: "Please Verify OTP!", success: false, otp_verify: false });
  }

  try {
    // Generate authentication tokens
    const accessToken = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1800s" });
    const refreshToken = jwt.sign({ email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "15d" });

    // Create user
    await User.create({
      name,
      email,
      password,
      age,
      gender,
      school,
      batch,
      bio,
      refresh_token: refreshToken,
    });

    // Clear cookies and set authentication tokens
    ["email", "password", "otp", "otp_verified"].forEach(cookie => res.clearCookie(cookie));
    return res
      .cookie("refreshToken", refreshToken, { httpOnly: true, maxAge: 15 * 24 * 60 * 60 * 1000 })
      .cookie("accessToken", accessToken, { httpOnly: true, maxAge: 30 * 60 * 1000 })
      .json({ msg: null, success: true, otp_verify: true });
  } catch (error) {
    console.error(error);
    return res.json({ msg: "Something Went Wrong! Please Try Again!", success: false, otp_verify: true });
  }
};

// Authenticate user login
export const login_post = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) throw new Error("User Not Found");

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.json({ msg: "Wrong Password", success: false });
    }

    // Generate authentication tokens
    const accessToken = jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1800s" });
    const refreshToken = jwt.sign({ email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "15d" });

    user.set({ refresh_token: refreshToken });
    await user.save();

    return res
      .cookie("refreshToken", refreshToken, { httpOnly: true, maxAge: 15 * 24 * 60 * 60 * 1000 })
      .cookie("accessToken", accessToken, { httpOnly: true, maxAge: 30 * 60 * 1000 })
      .json({ msg: null, success: true });
  } catch (error) {
    return res.json({ msg: "Email Not Found! Please Register First!", success: false });
  }
};

// Get user details
export const user_update_get = async (req, res) => {
  try {
    const currentUser = await User.findOne({ where: { email: req.user } });

    if (!currentUser) {
      return res.json({ msg: "User Not Found! Please Login or Register First!", success: false });
    }

    return res.json({
      msg: null,
      success: true,
      user: {
        name: currentUser.name,
        age: currentUser.age,
        gender: currentUser.gender,
        school: currentUser.school,
        batch: currentUser.batch,
        bio: currentUser.bio,
        type: currentUser.type,
        image_url: currentUser.image_url,
      },
    });
  } catch (error) {
    console.error(error);
    return res.json({ msg: "Something Went Wrong. Please Try Again!", success: false });
  }
};

// Update user details
export const user_update_post = async (req, res) => {
  const { name, age, gender, school, batch, bio, type } = req.body;

  try {
    const currentUser = await User.findOne({ where: { email: req.user } });

    if (!currentUser) {
      return res.json({ msg: "User Not Found! Please Login or Register First!", success: false });
    }

    const updates = { name, age, gender, school, batch, bio, type };
    let changesMade = false;

    for (const [key, value] of Object.entries(updates)) {
      if (currentUser[key] !== value) {
        currentUser.set({ [key]: value });
        changesMade = true;
      }
    }

    if (changesMade) {
      await currentUser.save();
      return res.json({ msg: "User Successfully Updated!", success: true });
    }

    return res.json({ msg: "No Changes Made. Please Make Changes Before Updating Profile!", success: false });
  } catch (error) {
    console.error(error);
    return res.json({ msg: "Something Went Wrong. Please Try Again!", success: false });
  }
};

// TODO: Forgot password controller
// 1. Get user email
// 2. Check DB
// 3. Send OTP
// 4. Verify OTP
