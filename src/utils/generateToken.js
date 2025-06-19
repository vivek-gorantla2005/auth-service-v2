import jwt from "jsonwebtoken"
import crypto from "crypto"
import RefreshToken from "../models/RefreshToken.js"


const generateToken = async (user) => {
  const accessToken = jwt.sign(
    {
      userId: user._id,
      username: user.username,
    },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );

  const refreshToken = crypto.randomBytes(40).toString("hex");
  const hashedToken = crypto.createHash("sha256").update(refreshToken).digest("hex");

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  await RefreshToken.create({
    token: hashedToken,
    user: user._id,
    expiresAt,
  });

  return { accessToken, refreshToken };
};

export default generateToken;
