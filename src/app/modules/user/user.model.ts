import mongoose, { Schema } from "mongoose";
import { IUser, UserRole } from "./user.interface";
import bcrypt from "bcrypt";
import config from "../../config";

// Create the User schema based on the interface
const userSchema = new Schema<IUser>(
  {
    firstName: {
      type: String,
      required: true,
    },
    lastName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: [
        UserRole.FOUNDER,
        UserRole.INFLUENCER,
        UserRole.INVESTOR,
        UserRole.SINGLE,
      ],
      required: true,
    },

    isActive: {
      type: Boolean,
      default: true,
    },
    otpToken: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  const user = this;

  user.password = await bcrypt.hash(
    user.password,
    Number(config.bcrypt_salt_rounds)
  );

  next();
});

userSchema.post("save", function (doc, next) {
  doc.password = "";
  next();
});

userSchema.statics.isPasswordMatched = async function (
  plainTextPassword,
  hashedPassword
) {
  return await bcrypt.compare(plainTextPassword, hashedPassword);
};

const User = mongoose.model<IUser>("User", userSchema);
export default User;
