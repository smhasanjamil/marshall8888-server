import { Document, Model } from 'mongoose';

// Enum for User Roles
export enum UserRole {
  INFLUENCER = 'influencer',
  FOUNDER = 'founder',
  INVESTOR = 'investor',
  SINGLE = 'single'
}


// User Schema Definition
export interface IUser extends Document {
   email: string;
   password: string;
   firstName: string;
   lastName: string;
   role: UserRole;
   isActive: boolean;
   otpToken?: string | null;
   createdAt: Date;
   updatedAt: Date;
}

