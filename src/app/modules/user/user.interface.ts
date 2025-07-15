import { Document } from "mongoose";

// Enum for User Roles
export enum UserRole {
  ADMIN = "admin",
  USER = "user",
  FOUNDER = "founder",
  INVESTOR = "investor",
  INFLUENCER = "influencer",
}

// User Interface
export interface IUser extends Document {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  role: UserRole;
  isActive: boolean;
  otpToken?: string | null;
  createdAt: Date;
  updatedAt: Date;
}
